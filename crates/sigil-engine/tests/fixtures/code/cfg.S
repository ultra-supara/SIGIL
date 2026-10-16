# CFG cases (PR-5a spec §8.1).
        .text
        .globl jumptable
        .type jumptable, @function
jumptable:                          # connect only after an unresolved indirect jump
        .cfi_startproc
        jmp *%rdi
        xor %edi, %edi
        xor %esi, %esi
        xor %edx, %edx
        call connect@PLT
        ret
        .cfi_endproc

        .globl after_noreturn
        .type after_noreturn, @function
after_noreturn:                     # data after a noreturn import, never decoded
        .cfi_startproc
        sub $8, %rsp
        .cfi_def_cfa_offset 16
        test %edi, %edi
        je 1f
        call abort@PLT
        .byte 0xff, 0xff
1:      xor %edi, %edi
        xor %esi, %esi
        xor %edx, %edx
        call connect@PLT
        add $8, %rsp
        .cfi_def_cfa_offset 8
        ret
        .cfi_endproc

        .globl into_insn
        .type into_insn, @function
into_insn:                          # a branch into the middle of an instruction
        .cfi_startproc
        test %edi, %edi
        jne 1f+1
1:      mov $0x90909090, %eax
        xor %edi, %edi
        xor %esi, %esi
        xor %edx, %edx
        call connect@PLT
        ret
        .cfi_endproc

        .globl noeh_code
        .type noeh_code, @function
noeh_code:                          # no CFI: no FDE
        xor %edi, %edi
        xor %esi, %esi
        xor %edx, %edx
        call connect@PLT
        ret

        .globl hot
        .type hot, @function
hot:
        .cfi_startproc
        test %edi, %edi
        jne cold_part
        ret
        .cfi_endproc

        .type cold_part, @function
cold_part:                          # a separate FDE entered at its start
        .cfi_startproc
        xor %edi, %edi
        xor %esi, %esi
        xor %edx, %edx
        call connect@PLT
        ud2
        .cfi_endproc
        .section .note.GNU-stack,"",@progbits
