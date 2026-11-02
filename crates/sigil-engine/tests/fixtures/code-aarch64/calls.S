/* Explicit ABI/format conditionals: this is assembled, never a patched dump. */
#ifdef __APPLE__
#define C(name) _##name
#else
#define C(name) name
#endif
#define BEGIN(name) begin C(name)
#define END(name) end C(name)

.text
.macro begin name
  .p2align 2
  .globl \name
#ifndef __APPLE__
  .type \name, %function
#endif
\name:
  .cfi_startproc
#ifdef __APPLE__
  /* Harmless DW_CFA_GNU_args_size(0) forces a DWARF-mode compact entry. */
  .cfi_escape 0x2e, 0x00
#endif
.endm
.macro end name
  .cfi_endproc
#ifndef __APPLE__
  .size \name, .-\name
#endif
.endm
#if defined(__aarch64__)
.macro enter
  stp x29, x30, [sp, #-16]!
  .cfi_def_cfa_offset 16
  .cfi_offset x29, -16
  .cfi_offset x30, -8
  mov x29, sp
  .cfi_def_cfa_register x29
.endm
.macro leave
  ldp x29, x30, [sp], #16
  .cfi_def_cfa sp, 0
  .cfi_restore x29
  .cfi_restore x30
  ret
.endm
.macro zeros
  mov w0, wzr
  mov x1, xzr
  mov w2, wzr
.endm
BEGIN(asm_zero)
  enter
  zeros
  bl C(connect)
  leave
END(asm_zero)
BEGIN(copy)
  enter
  mov w3, wzr
  mov w0, w3
  mov x1, xzr
  mov w2, wzr
  bl C(connect)
  leave
END(copy)
BEGIN(join_agree)
  enter
  cbz x0, 1f
  mov w0, #0
  b 2f
1: mov w0, wzr
2: mov x1, xzr
  mov w2, wzr
  bl C(connect)
  leave
END(join_agree)
BEGIN(join_disagree)
  enter
  cbz x0, 1f
  mov w0, #1
  b 2f
1: mov w0, wzr
2: mov x1, xzr
  mov w2, wzr
  bl C(connect)
  leave
END(join_disagree)
BEGIN(caller_clobber)
  enter
  zeros
  mov x16, #16
  mov x17, #17
  bl C(helper)
  mov w0, w16
  bl C(connect)
  leave
END(caller_clobber)
BEGIN(helper)
  mov w0, #7
  ret
END(helper)
/* Reserved reachable word: future decoding must roll back the whole function. */
BEGIN(malformed_reserved)
  enter
  zeros
  .inst 0x00000000
  bl C(connect)
  leave
END(malformed_reserved)
BEGIN(unsupported_indirect)
  br x8
END(unsupported_indirect)
BEGIN(unsupported_pac)
  .inst 0xd503233f /* PACIASP, deliberately outside the initial whitelist. */
  ret
END(unsupported_pac)
#elif defined(__x86_64__)
.macro enter
  pushq %rbp
  .cfi_def_cfa_offset 16
  .cfi_offset %rbp, -16
  movq %rsp, %rbp
  .cfi_def_cfa_register %rbp
.endm
.macro leave
  popq %rbp
  .cfi_def_cfa %rsp, 8
  retq
.endm
.macro zeros
  xorl %edi, %edi
  xorl %esi, %esi
  xorl %edx, %edx
.endm
BEGIN(asm_zero)
  enter
  zeros
  callq C(connect)
  leave
END(asm_zero)
BEGIN(copy)
  enter
  xorl %eax, %eax
  movl %eax, %edi
  xorl %esi, %esi
  xorl %edx, %edx
  callq C(connect)
  leave
END(copy)
BEGIN(join_agree)
  enter
  testl %edi, %edi
  jz 1f
  movl $0, %edi
  jmp 2f
1: xorl %edi, %edi
2: xorl %esi, %esi
  xorl %edx, %edx
  callq C(connect)
  leave
END(join_agree)
BEGIN(join_disagree)
  enter
  testl %edi, %edi
  jz 1f
  movl $1, %edi
  jmp 2f
1: xorl %edi, %edi
2: xorl %esi, %esi
  xorl %edx, %edx
  callq C(connect)
  leave
END(join_disagree)
BEGIN(caller_clobber)
  enter
  zeros
  callq C(helper)
  movl %r11d, %edi
  callq C(connect)
  leave
END(caller_clobber)
BEGIN(helper)
  movl $7, %eax
  retq
END(helper)
BEGIN(malformed_reserved)
  enter
  zeros
  ud2
  callq C(connect)
  leave
END(malformed_reserved)
BEGIN(unsupported_indirect)
  jmpq *%r11
END(unsupported_indirect)
BEGIN(malformed_overlap)
  .byte 0x75, 0x01 /* branch into the following immediate */
  movl $0x90909090, %eax
  retq
END(malformed_overlap)
#else
#error unsupported fixture assembly architecture
#endif

#ifndef __APPLE__
.section .note.GNU-stack,"",%progbits
#endif
