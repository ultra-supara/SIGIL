extern int connect(int, const void *, unsigned int);
extern void keep(int (*)(int, const void *, unsigned int));
void take(void) { keep(connect); }
