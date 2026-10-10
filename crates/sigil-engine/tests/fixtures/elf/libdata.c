/* Fixture: SONAME, NEEDED (libm, libc), RUNPATH, build-id, versioned imports, exports, and the
 * four known data symbols through R_X86_64_RELATIVE. */
#include <math.h>
#include <sys/socket.h>

const char *LLAMA_COMMIT = "6f3a9f3de";
const char *LLAMA_COMPILER = "GNU 11.2.1";
const char *LLAMA_BUILD_TARGET = "x86_64-linux-gnu";
int LLAMA_BUILD_NUMBER = 1;

double sigil_fixture_sqrt(double x) { return sqrt(x); }
int sigil_fixture_connect(int fd) { return connect(fd, 0, 0); }
