#include <dlfcn.h>
void *score(void *h) { return dlsym(h, "ggml_backend_score"); }
void *byname(void *h, int k) {
    char buf[32];
    for (int i = 0; i < 31; i++) buf[i] = (char)('a' + (k + i) % 26);
    buf[31] = 0;
    return dlsym(h, buf);
}
