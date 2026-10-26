/* #51: one direct call of execve and one of connect, for policy rules over call sites. */
extern int execve(const char *, char *const *, char *const *);
extern int connect(int, const void *, unsigned int);
int run(const char *path, char *const *argv, char *const *envp) { return execve(path, argv, envp) + 1; }
int dial(int fd) { return connect(fd, 0, 0) + 1; }
