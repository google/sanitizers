#include <assert.h>
#include <dirent.h>
#include <regex>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <set>
#include <map>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#define PTRACE_PEEKMTETAGS 33

template <typename T>
std::string hex_to_string(T x) {
  std::stringstream sstream;
  sstream << std::hex << x;
  std::string result = sstream.str();
  return result;
}

typedef unsigned long uptr;

struct Map {
  uptr start, end;
  std::string name;
  uptr rss, pss;
  uptr shadow_pages;
  unsigned prot;
  bool mt;
  Map(uptr start, uptr end, const std::string &p, const std::string &name)
      : start(start),
        end(end),
        name(name),
        rss(0),
        pss(0),
        shadow_pages(0),
        prot(0),
        mt(false) {
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

void read_maps(int pid, std::vector<Map*> &maps) {
  std::regex name_regex(
      "([01-9a-f]+)-([01-9a-f]+) ([a-z-]{4}) [01-9a-f]+ "
      "[01-9a-f]{2}:[01-9a-f]{2} [01-9a-f]+\\s*(.*)?");
  std::regex rss_regex("Rss:\\s+(\\d+) kB");
  std::regex pss_regex("Pss:\\s+(\\d+) kB");
  std::regex vmflags_regex("VmFlags:(.+)");

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
    } else if (std::regex_match(line, match, vmflags_regex)) {
      assert(match.size() == 2);
      assert(current);
      current->mt = match[1].str().find(" mt") != std::string::npos;
    }
  }
  if (current)
    maps.push_back(current);
}

uint64_t get_pfn(int pagemapfd, size_t addr) {
  size_t pagemap_offset = (addr / 4096) * 8;
  uint64_t pagemap_entry;
  if (pread(pagemapfd, &pagemap_entry, 8, pagemap_offset) != 8) {
    perror("pread pagemap");
    exit(1);
  }

  if (!(pagemap_entry & (1ULL << 63))) {
    return 0;
  }

  return pagemap_entry & ((1ULL << 55) - 1);
}

std::set<uint64_t> seen_pfns;
int outfd;

void dump_map_tags(int pid, int pagemapfd, Map *m) {
  assert(m->start % 4096 == 0);
  assert(m->end % 4096 == 0);
  std::cerr << "dumping: " << (void *)m->start << " .. " << (void *)m->end << "  " << m->name;

  uint64_t total = 0, present = 0, dumped = 0;
  for (uptr addr = m->start; addr != m->end; addr += 4096) {
    ++total;
    uint64_t pfn = get_pfn(pagemapfd, addr);
    if (pfn == 0)
      continue;
    ++present;
    if (!seen_pfns.insert(pfn).second)
      continue;
    ++dumped;

    constexpr uptr size = 4096 / 16;
    char buf[size];
    iovec iov = {buf, size};
    long res = ptrace(PTRACE_PEEKMTETAGS, pid, (void *)addr, &iov);
    if (res != 0) {
      perror("peekmtetags");
      exit(1);
    }
    assert(res == 0 && iov.iov_len == size);

    if (write(outfd, buf, size) != size) {
      perror("write");
      exit(1);
    }
  }

  std::cerr << ": " << total << " pages, " << present << " present" << ", " << dumped << " dumped\n";
}

void dump_pid_tags(int pid) {
  int pagemapfd = open(("/proc/" + std::to_string(pid) + "/pagemap").c_str(), O_RDONLY);
  if (pagemapfd < 0) {
    perror("open pagemap");
    exit(1);
  }

  int res = ptrace(PTRACE_ATTACH, pid, nullptr, nullptr);
  if (res != 0) {
    perror("ptrace attach");
    exit(1);
  }

  std::vector<Map*> maps;
  read_maps(pid, maps);

  for (auto m : maps) {
    if (!m->mt)
      continue;
    dump_map_tags(pid, pagemapfd, m);
  }

  res = ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
  if (res != 0) {
    perror("ptrace attach");
    exit(1);
  }

  close(pagemapfd);
}

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "arg required\n";
    return 1;
  }
  outfd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (outfd < 0) {
    perror("open");
    exit(1);
  }

  DIR *proc = opendir("/proc");
  if (!proc) {
    perror("opendir");
    exit(1);
  }

  while (dirent *ent = readdir(proc)) {
    char *end;
    int pid = strtol(ent->d_name, &end, 10);
    if (*end != 0) {
      continue;
    }
    if (pid == getpid()) {
      continue;
    }
    
    char exe[256];
    size_t exe_size = readlink(
        ("/proc/" + std::to_string(pid) + "/exe").c_str(), exe, sizeof(exe));
    if (exe_size == -1) {
      // Skip kernel threads.
      if (errno == ENOENT) {
        continue;
      }
      perror("readlink");
      exit(1);
    }

    if (exe_size >= sizeof(exe)) {
      exe_size = sizeof(exe) - 1;
    }
    exe[exe_size] = 0;

    std::cerr << "dumping pid " << pid << ": " << exe << '\n';
    dump_pid_tags(pid);
  }

  closedir(proc);
}
