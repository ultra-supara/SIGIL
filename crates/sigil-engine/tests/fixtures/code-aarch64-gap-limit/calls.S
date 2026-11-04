// Boundary fixture: one independently complete function, then CALLS partial layouts.
.text
.globl healthy
.type healthy,%function
healthy:
.cfi_startproc
stp x29, x30, [sp, #-16]!
mov x29, sp
mov w0, #0
mov x1, #0
mov w2, #0
bl connect
ldp x29, x30, [sp], #16
ret
.cfi_endproc
.size healthy, .-healthy
.globl many
.type many,%function
many:
.cfi_startproc
stp x29, x30, [sp, #-16]!
mov x29, sp
.rept CALLS
bl execve
.endr
ldp x29, x30, [sp], #16
ret
.cfi_endproc
.size many, .-many
