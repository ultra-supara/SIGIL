# ET_REL relocations that do not name a call (PR-5a spec §4.2 table).
        .text
        .globl g
        .type g, @function
g:
        .cfi_startproc
        call *connect@GOTPCREL+4(%rip)      # GOTPCRELX not exact: gap
        lea connect@GOTPCREL(%rip), %rax    # a lea of a GOT entry: Unknown, gap
        cmp %rax, connect@GOTPCREL(%rip)    # read, not called: address taken
        lea connect@PLT(%rip), %rcx         # PLT32 on a non-branch field: gap
        mov extern_data(%rip), %rdx         # PC32 against undefined data: Unknown, no gap
        ret
        .cfi_endproc
        .section .note.GNU-stack,"",@progbits
