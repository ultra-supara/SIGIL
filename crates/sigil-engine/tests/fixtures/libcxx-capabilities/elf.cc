// The ELF of the libc++ capability fixture (build.sh, #105). Never run. It calls six functions
// whose libc++ names the capability table maps, and four whose names it does not.
#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;

int main(int argc, char** argv) {
  if (argc < 3)
    return 2;
  fs::path a = argv[1], b = argv[2];
  std::error_code ec;
  // Mapped, cxx.file_write: each imports its __fs::filesystem helper.
  fs::remove(a, ec);
  fs::rename(a, b);
  fs::create_directories(a);
  fs::copy_file(a, b, fs::copy_options::overwrite_existing);
  // Mapped: open with a file name (cxx.file_read, cxx.file_write).
  std::ifstream in;
  in.open(argv[1]);
  std::ofstream out;
  out.open(std::string(argv[2]));
  // Unmapped: a stream constructor that opens imports basic_filebuf::open; permissions and
  // last_write_time are metadata; exists is inline over __status.
  std::fstream io(argv[1]);
  fs::permissions(a, fs::perms::owner_all);
  auto t = fs::last_write_time(a);
  bool exists = fs::exists(a);
  return in.good() + out.good() + io.good() + exists + (t == decltype(t){});
}
