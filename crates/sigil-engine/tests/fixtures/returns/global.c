/* Fixture (PR-4c-2b): ggml_version returns a pointer loaded from a global, which another
 * library may interpose: no constant address. */
const char *v = "0.13.1";

const char *ggml_version(void) { return v; }
const char *ggml_commit(void) { return "6f3a9f3de"; }
