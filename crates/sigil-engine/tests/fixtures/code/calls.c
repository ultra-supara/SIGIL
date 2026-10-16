/* ET_REL -fno-plt fixtures (PR-5a spec rev. 2, review P1-1). */
extern int connect(int, const void *, unsigned int);
__attribute__((noinline)) int helper(int x) { return x * 3; }
int kernel(int a) { return connect(a, 0, 0); }
int loop(int n) { int s = 0; for (int i = 0; i < n; i++) s += connect(i, 0, 0); return s; }
int calls_helper(int a) { return connect(helper(a), 0, 0); }
