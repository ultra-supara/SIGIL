extern int connect(int, const void *, unsigned int);
int (*const table[])(int, const void *, unsigned int) = { connect };
