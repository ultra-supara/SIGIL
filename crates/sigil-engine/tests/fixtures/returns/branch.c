/* Fixture (PR-4c-2b): ggml_version picks one of two strings: two paths, not one block. */
int release;

const char *ggml_version(void) {
    if (release)
        return "0.13.1";
    return "0.13.1-dev";
}
const char *ggml_commit(void) { return "6f3a9f3de"; }
