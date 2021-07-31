#include <assert.h>
#include <regex>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <set>
#include <map>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/uio.h>

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

void dump_tags(const std::string prefix, int pid, Map *m) {
  assert(m->start % 4096 == 0);
  assert(m->end % 4096 == 0);
  std::cerr << "dumping: " << (void *)m->start << " .. " << (void *)m->end << "  " << m->name << "\n";

  uptr size = (m->end - m->start) / 16;
  auto buf = std::make_unique<char[]>(size);
  iovec iov = {buf.get(), size};
  long res = ptrace(PTRACE_PEEKMTETAGS, pid, (void *)m->start, &iov);
  if (res != 0) {
    perror("peekmtetags");
  }
  assert(res == 0 && iov.iov_len == size);

  std::string path = prefix + "/tags_" + std::to_string(pid) + "_" + hex_to_string(m->start);
  std::ofstream out(path);
  out.write(buf.get(), size);
}

int main(int argc, char **argv) {
  if (argc < 3) {
    std::cerr << "arg required\n";
    return 1;
  }
  int pid = atoi(argv[1]);
  std::string prefix = argv[2];
  int res;

  res = ptrace(PTRACE_ATTACH, pid, nullptr, nullptr);
  if (res != 0) {
    perror("ptrace attach");
    exit(1);
  }

  std::vector<Map*> maps;
  read_maps(pid, maps);

  for (auto m : maps) {
    if (!m->mt)
      continue;
    dump_tags(prefix, pid, m);
  }

  res = ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
  if (res != 0) {
    perror("ptrace attach");
    exit(1);
  }
}
