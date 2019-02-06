#include <assert.h>
#include <regex>
#include <fstream>
#include <string>
#include <set>
#include <map>
#include <sys/mman.h>

typedef unsigned long uptr;

struct Map {
  uptr start, end;
  std::string name;
  uptr rss, pss;
  uptr shadow_pages;
  unsigned prot;
  Map(uptr start, uptr end, const std::string &p, const std::string &name)
      : start(start),
        end(end),
        name(name),
        rss(0),
        pss(0),
        shadow_pages(0),
        prot(0) {
    assert(p[0] == 'r' || p[0] == '-');
    assert(p[1] == 'w' || p[1] == '-');
    assert(p[2] == 'x' || p[2] == '-');
    if (p[0] == 'r')
      prot |= PROT_READ;
    if (p[1] == 'w')
      prot |= PROT_WRITE;
    if (p[2] == 'x')
      prot |= PROT_EXEC;
  }
};


class PageFlagsReader {
  std::map<uptr, uptr> flags;
  FILE *fp;

  void LoadFlags(uptr pfn) {
    int res = fseek(fp, pfn * 8, SEEK_SET);
    assert(!res);
    uptr x;
    res = fread(&x, 8, 1, fp);
    assert(res == 1);
    flags[pfn] = x;
  }

  uptr GetFlags(uptr pfn) {
    auto it = flags.find(pfn);
    if (it == flags.end()) {
      LoadFlags(pfn);
      it = flags.find(pfn);
    }
    return it->second;
  }

 public:
  PageFlagsReader() {
    fp = fopen("/proc/kpageflags", "rb");
    assert(fp);
  }

  bool IsZeroPage(uptr pfn) {
    uptr x = GetFlags(pfn);
    bool zero = (x >> 24) & 1;
    return zero;
  }
};

PageFlagsReader *PFR;

void read_maps(int pid, std::vector<Map*> &maps) {
  std::regex name_regex(
      "([01-9a-f]+)-([01-9a-f]+) ([a-z-]{4}) [01-9a-f]+ "
      "[01-9a-f]{2}:[01-9a-f]{2} [01-9a-f]+\\s*(.*)?");
  std::regex rss_regex("Rss:\\s+(\\d+) kB");
  std::regex pss_regex("Pss:\\s+(\\d+) kB");

  maps.clear();
  std::string path = "/proc/" + std::to_string(pid) + "/smaps";
  std::ifstream smaps(path);
  std::string line;
  Map *current = nullptr;
  while (std::getline(smaps, line)) {
    std::smatch match;
    if (std::regex_match(line, match, name_regex)) {
      assert(match.size() == 5);
      if (current)
        maps.push_back(current);
      uptr start = stoul(match[1].str(), 0, 16);
      uptr end = stoul(match[2].str(), 0, 16);
      current = new Map(start, end, match[3], match[4]);
    } else if (std::regex_match(line, match, rss_regex)) {
      assert(match.size() == 2);
      assert(current);
      current->rss = stoul(match[1].str());
    } else if (std::regex_match(line, match, pss_regex)) {
      assert(match.size() == 2);
      assert(current);
      current->pss = stoul(match[1].str());
    }
  }
  if (current)
    maps.push_back(current);
}

void scan(FILE *fp, uptr addr, uptr start_ofs, uptr end_ofs, std::vector<uptr> &resident_pages) {
  uptr num_resident = 0;
  int res = fseek(fp, start_ofs, SEEK_SET);
  assert(!res);
  constexpr uptr kPfnMask = (((uptr)1) << 54) - 1;
  std::set<uptr> pfns;

  uptr ofs = start_ofs;
  constexpr uptr kBufSize = 1024;
  uptr buf[1024];
  uptr buf_idx = 0;
  uptr buf_size = 0;
  while (ofs < end_ofs) {
    if (buf_idx >= buf_size) {
      buf_size = fread(buf, sizeof(uptr), std::min((end_ofs - ofs) / 8, kBufSize), fp);
      assert(buf_size >= 0);
      buf_idx = 0;
    }
    uptr v = buf[buf_idx];
    bool resident = (v >> 63) & 1;
    if (resident) {
      uptr pfn = v & kPfnMask;
      if (!PFR->IsZeroPage(pfn)) {
        ++num_resident;
        pfns.insert(pfn);
        resident_pages.push_back(addr);
      }
    }
    ++buf_idx;
    ofs += 8;
    addr += 4096;
  }
}

void scan_pagemap(int pid, std::vector<Map*> &maps, Map *low_shadow, std::vector<uptr> &resident_pages) {
  std::string pagemap = "/proc/" + std::to_string(pid) + "/pagemap";
  FILE *fp = fopen(pagemap.c_str(), "rb");
  assert(fp);

  scan(fp, low_shadow->start, low_shadow->start / 4096 * 8,
       low_shadow->end / 4096 * 8, resident_pages);
}

static bool compare(const Map* m, uptr v) {
  return m->end <= v;
}

Map *find_map(std::vector<Map*> &maps, uptr addr) {
  auto it = std::lower_bound(maps.begin(), maps.end(), addr, compare);
  if (it == maps.end())
    return nullptr;
  uptr start = (*it)->start;
  uptr end = (*it)->end;
  assert(addr < end);
  if (addr < start)
    return nullptr;
  return *it;
}

// Map resident shadow pages back to user pages, and associate those with user
// mappings. Make a half-assed attempt to account for user pages that are just
// outside of a mapping (or within a non-read-write mapping), but still within
// shadow granularity.
//
// Return the number of pages that were not within or nearby an r-or-w mapping.
uptr do_magic(uptr base, std::vector<Map*> &maps, std::vector<uptr> &resident_shadow_pages) {
  uptr unallocated = 0;
  for (uptr shadow : resident_shadow_pages) {
    uptr user0 = (shadow - base) * 16;
    uptr unknown_pages = 0;
    Map *last_map = nullptr;
    for (uptr x = 0; x < 16; ++x) {
      uptr user = user0 + x * 4096;
      Map *m = find_map(maps, user);
      if (m && (m->prot & (PROT_READ | PROT_WRITE)) == 0) m = nullptr;
      if (m) {
        m->shadow_pages += (1 + unknown_pages);
        unknown_pages = 0;
        last_map = m;
      } else if (last_map) {
        last_map->shadow_pages++;
      } else {
        unknown_pages++;
      }
    }
    unallocated += unknown_pages;
  }
  return unallocated;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "arg required\n");
    return 1;
  }
  int pid = atoi(argv[1]);

  PFR = new PageFlagsReader();

  std::vector<Map*> maps;
  read_maps(pid, maps);

  printf("========================================\n");
  printf("     start           end       RSS   PSS\n");
  for (auto *map : maps)
    printf("%10lx .. %10lx %c%c%c %5lu %5lu %s\n", map->start, map->end,
           (map->prot & PROT_READ) ? 'r' : '-',
           (map->prot & PROT_WRITE) ? 'w' : '-',
           (map->prot & PROT_EXEC) ? 'x' : '-', map->rss, map->pss,
           map->name.c_str());

  Map *low_shadow = nullptr;
  Map *high_shadow = nullptr;
  for (auto *map : maps) {
    if (map->name == "[anon:low shadow]") {
      low_shadow = map;
    } else if (map->name == "[anon:high shadow]") {
      high_shadow = map;
    }
  }

  if (!low_shadow || !high_shadow) {
    fprintf(stderr, "shadow mapping not found\n");
    return 1;
  }

  printf("========================================\n");
  printf("Low shadow: %zx .. %zx\n", low_shadow->start, low_shadow->end);
  printf("High shadow: %zx .. %zx\n", high_shadow->start, high_shadow->end);

  std::vector<uptr> resident_shadow_pages;
  scan_pagemap(pid, maps, low_shadow, resident_shadow_pages);
  scan_pagemap(pid, maps, high_shadow, resident_shadow_pages);
  printf("%lu resident shadow pages\n", resident_shadow_pages.size());

  uptr base = low_shadow->start;
  uptr unallocated = do_magic(base, maps, resident_shadow_pages);

  printf("==============================================\n");
  printf("     start           end      size   RSS  SRSS\n");
  for (auto *map : maps) {
    if (map->shadow_pages == 0)
      continue;
    printf("%10lx .. %10lx  %8lu %5lu %5lu %s\n", map->start, map->end,
           (map->end - map->start) / 1024, map->rss,
           map->shadow_pages * 4096 / 1024, map->name.c_str());
  }

  printf("Shadow RSS: %lu unaccounted, %lu total\n", unallocated, resident_shadow_pages.size() * 16);
}
