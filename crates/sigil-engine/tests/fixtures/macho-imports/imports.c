/* The program of the imports-universal fixture (build.sh, PR-4c-3b). It imports three capability
 * functions from libSystem (connect, getenv, dlopen), puts, which is not one, and from libfoo,
 * another dylib, socket and a weak sigil_weak. Never run. */
extern int connect(int, const void *, unsigned int);
extern char *getenv(const char *);
extern void *dlopen(const char *, int);
extern int puts(const char *);
extern int socket(int, int, int);
extern int sigil_weak(void) __attribute__((weak_import));

int main(void) {
    if (getenv("SIGIL_FIXTURE") == 0)
        return puts("sigil") < 0;
    if (sigil_weak)
        sigil_weak();
    return connect(socket(2, 1, 0), 0, 0) + (dlopen(0, 0) != 0);
}
