# One text relocation and one PLT call to the same capability. The legacy path admits one
# reference of each kind at references=1; multiarch must share that single allowance.
        .text
        .globl shared_refs
        .type shared_refs, @function
shared_refs:
        .cfi_startproc
        movabs $connect, %rax
        call *%rax
        call connect@PLT
        ret
        .cfi_endproc
        .section .note.GNU-stack,"",@progbits
