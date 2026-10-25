// A class derived from std::ifstream (PR-4c-3c), built with g++ -O0 so that its constructor calls
// basic_ifstream's base-object constructor (C2), which takes the VTT as its second argument. At
// -O2, g++ inlines that constructor and imports basic_filebuf::open instead.
#include <fstream>

struct config_file : std::ifstream {
  explicit config_file(const char* path) : std::ifstream(path) {}
};

int derived(const char* path) {
  config_file f(path);
  return f.good();
}
