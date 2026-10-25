// The C++ capability fixture's main unit (PR-4c-3c), built with g++ -O2 and libstdc++'s default
// ABI (std::filesystem::__cxx11::path, std::__cxx11::string). It is never run: it exists for its
// imports. Mapped (cxx.*): an ifstream and an ofstream opened by name, and four std::filesystem
// operations. Unmapped (spec §3): an fstream, filebuf::open, permissions, last_write_time,
// status, and a directory_iterator.
#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;

int old_abi(const char* path);  // old_abi.cc
int derived(const char* path);  // derived.cc

int main(int argc, char** argv) {
  if (argc < 3) return 2;
  std::ifstream in(argv[1]);
  std::ofstream out{std::string(argv[2])};
  std::error_code ec;
  fs::remove(argv[1], ec);
  fs::rename(argv[1], argv[2]);
  fs::create_directories(argv[2]);
  fs::copy_file(argv[1], argv[2], fs::copy_options::overwrite_existing);
  // Unmapped: the mode decides read or write, or nothing is written.
  std::fstream both(argv[1], std::ios::in | std::ios::out);
  std::filebuf buf;
  buf.open(argv[2], std::ios::in);
  fs::permissions(argv[1], fs::perms::owner_all);
  auto when = fs::last_write_time(argv[1]);
  auto st = fs::status(argv[1]);
  int n = 0;
  for (auto& e : fs::directory_iterator(argv[2])) n += e.is_regular_file();
  return in.good() + out.good() + both.good() + (st.type() == fs::file_type::regular) + n +
         (when.time_since_epoch().count() > 0) + old_abi(argv[1]) + derived(argv[2]);
}
