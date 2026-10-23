/* Fixture (PR-4c-2b): ggml's two version functions, as upstream defines them in ggml.c: each
 * returns the address of a constant string. VERSION is set by build.sh for one build. */
#ifndef VERSION
#define VERSION "0.13.1"
#endif

const char *ggml_version(void) { return VERSION; }
const char *ggml_commit(void) { return "6f3a9f3de"; }
