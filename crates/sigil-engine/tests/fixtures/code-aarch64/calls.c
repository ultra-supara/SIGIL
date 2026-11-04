/* Headerless so both pinned cross toolchains need no target libc/sysroot. */
extern int connect(int, const void *, unsigned);

#ifdef FORCE_DWARF
/* Valid DW_CFA_GNU_args_size(0); no machine instruction or argument change. */
#define FDE_PROOF() __asm__ volatile(".cfi_escape 0x2e, 0x00")
#else
#define FDE_PROOF() ((void)0)
#endif

__attribute__((noinline)) int zero(void) { FDE_PROOF(); return connect(0, 0, 0) + 1; }
__attribute__((noinline)) int one(void) { FDE_PROOF(); return connect(1, 0, 0) + 1; }

#ifdef DUPLICATE_NAMES
/* Equal-length spelling is renamed in the synthetic duplicate-name fixture. */
extern int connec2(int, const void *, unsigned);
__attribute__((noinline)) int from_foo(void) { FDE_PROOF(); return connec2(2, 0, 0) + 1; }
#endif
