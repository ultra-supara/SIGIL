extern int connect(int, const void *, unsigned int);
__attribute__((noinline)) void keep(int (*f)(int, const void *, unsigned int)) {
    void *volatile p = (void *)f; (void)p;
}
int main(void) { keep(connect); return 0; }
