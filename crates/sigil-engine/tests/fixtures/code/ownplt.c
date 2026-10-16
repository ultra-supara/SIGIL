extern int connect(int, const void *, unsigned int);
__attribute__((noinline)) int helper(int x) { return x + 7; }
int kernel(int a) { return connect(helper(a), 0, 0); }
