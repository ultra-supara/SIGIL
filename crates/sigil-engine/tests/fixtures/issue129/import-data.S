.text
.global simple
.type simple,%function
simple:
.cfi_startproc
 ret
.cfi_endproc
.size simple, .-simple
.data
.quad connect
