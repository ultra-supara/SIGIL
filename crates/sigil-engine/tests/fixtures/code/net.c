extern int connect(int, const void *, unsigned int);
int kernel(int fd) { return connect(fd, 0, 0) + 1; }
int looped(int n) { int s = 0; for (int i = 0; i < n; i++) s += connect(i, 0, 0); return s; }
