// The old-ABI unit (PR-4c-3c), built with g++ -O0 -D_GLIBCXX_USE_CXX11_ABI=0: std::string and
// std::filesystem::path of the ABI before GCC 5, whose names libstdc++ still exports. At -O2, g++
// inlines the ofstream constructor on the old string, which then imports basic_filebuf::open.
#include <filesystem>
#include <fstream>
#include <string>

int old_abi(const char* path) {
  std::ofstream out{std::string(path)};
  std::filesystem::remove(path);
  return out.good();
}
