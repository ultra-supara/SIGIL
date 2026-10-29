// The Mach-O of the libc++ capability fixture (build.sh, #105). Never run. It declares the libc++
// functions it calls rather than including libc++'s headers, so no macOS SDK is needed: the
// helpers std::filesystem::remove and permissions call, and connect and getenv.
namespace std {
inline namespace __1 {
class error_code;
namespace __fs {
namespace filesystem {
class path;
enum class perms : unsigned;
enum class perm_options : unsigned char;
bool __remove(const path&, error_code*);
void __permissions(const path&, perms, perm_options, error_code*);
} // namespace filesystem
} // namespace __fs
} // namespace __1
} // namespace std

extern "C" int connect(int, const void*, unsigned);
extern "C" char* getenv(const char*);

namespace fs = std::__fs::filesystem;

int main(int, char** argv) {
  const fs::path& p = *reinterpret_cast<const fs::path*>(argv[1]);
  if (getenv("SIGIL_FIXTURE") == nullptr)
    return 1;
  fs::__permissions(p, fs::perms(0700), fs::perm_options(1), nullptr);
  return fs::__remove(p, nullptr) + connect(0, nullptr, 0);
}
