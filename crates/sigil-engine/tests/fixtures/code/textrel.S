# A text relocation against connect (PR-5a spec §4.4).
        .text
        .globl tr
        .type tr, @function
tr:
        .cfi_startproc
        movabs $connect, %rax
        call *%rax
        ret
        .cfi_endproc
        .section .note.GNU-stack,"",@progbits
