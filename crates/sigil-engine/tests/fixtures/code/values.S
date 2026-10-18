# Value forms ending in a connect call (PR-5a spec §8.1).
        .text
        .section .rodata.str1.1,"aMS",@progbits,1
.Lname: .string "OLLAMA_HOST"
        .data
.Lbuf:  .quad 0
        .text

        .globl getenv_shape
        .type getenv_shape, @function
getenv_shape:                       # F-C4: rdi = ReturnOf(getenv) across blocks
        .cfi_startproc
        sub $8, %rsp
        .cfi_def_cfa_offset 16
        lea .Lname(%rip), %rdi
        call getenv@PLT
        test %rax, %rax
        je 1f
        mov %rax, %rdi
        xor %esi, %esi
        xor %edx, %edx
        call connect@PLT
1:      add $8, %rsp
        .cfi_def_cfa_offset 8
        ret
        .cfi_endproc

        .globl merge_shape
        .type merge_shape, @function
merge_shape:                        # F-C4 negative: rdi = Set{5, ReturnOf(getenv)}
        .cfi_startproc
        sub $8, %rsp
        .cfi_def_cfa_offset 16
        lea .Lname(%rip), %rdi
        call getenv@PLT
        test %rax, %rax
        jne 1f
        mov $5, %eax
1:      mov %rax, %rdi
        xor %esi, %esi
        xor %edx, %edx
        call connect@PLT
        add $8, %rsp
        .cfi_def_cfa_offset 8
        ret
        .cfi_endproc

        .type local_helper, @function
local_helper:
        .cfi_startproc
        ret
        .cfi_endproc

        .globl saved_rbx
        .type saved_rbx, @function
saved_rbx:                          # F-C5: Param(0) survives in rbx
        .cfi_startproc
        push %rbx
        .cfi_def_cfa_offset 16
        mov %rdi, %rbx
        call local_helper
        mov %rbx, %rdi
        xor %esi, %esi
        xor %edx, %edx
        call connect@PLT
        pop %rbx
        .cfi_def_cfa_offset 8
        ret
        .cfi_endproc

        .globl saved_rsi
        .type saved_rsi, @function
saved_rsi:                          # F-C5 negative: rsi is clobbered by the call
        .cfi_startproc
        sub $8, %rsp
        .cfi_def_cfa_offset 16
        mov %rdi, %rsi
        call local_helper
        mov %rsi, %rdi
        xor %esi, %esi
        xor %edx, %edx
        call connect@PLT
        add $8, %rsp
        .cfi_def_cfa_offset 8
        ret
        .cfi_endproc

        .globl loads
        .type loads, @function
loads:                              # Load depth 3, then 4; movzx
        .cfi_startproc
        sub $8, %rsp
        .cfi_def_cfa_offset 16
        mov 8(%rdi), %rax
        mov 16(%rax), %rcx
        mov 24(%rcx), %rdi          # depth 3: Load(Load(Load(Param0,+8),+16),+24)
        mov 32(%rdi), %rdx          # depth 4: Unknown(NotModeled)
        movzbl 5(%rsi), %esi        # Load(Param1, +5, 8)
        call connect@PLT
        add $8, %rsp
        .cfi_def_cfa_offset 8
        ret
        .cfi_endproc

        .globl partial
        .type partial, @function
partial:                            # Low 32, movsx, an 8-bit write, a high-byte write
        .cfi_startproc
        sub $8, %rsp
        .cfi_def_cfa_offset 16
        mov %edi, %edi              # Low(Param0, 32)
        movsbl (%rsi), %esi         # Unknown(NotModeled)
        mov $7, %dl                 # Low(Const 7, 8)
        mov $1, %ch                 # rcx: Unknown(NotModeled)
        call connect@PLT
        add $8, %rsp
        .cfi_def_cfa_offset 8
        ret
        .cfi_endproc

        .globl strs
        .type strs, @function
strs:                               # ConstStr, ConstInt immediate, ConstInt writable address
        .cfi_startproc
        sub $8, %rsp
        .cfi_def_cfa_offset 16
        lea .Lname(%rip), %rdi
        mov $0x2000, %esi
        lea .Lbuf(%rip), %rdx
        call connect@PLT
        add $8, %rsp
        .cfi_def_cfa_offset 8
        ret
        .cfi_endproc
        .section .note.GNU-stack,"",@progbits
