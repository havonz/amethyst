.align 4
.global _injection_shellcode_arm64_ios11

_injection_shellcode_arm64_ios11:
    mov     x0, sp
    sub     x0, x0, #0x10
    mov     x1, xzr
    adr     x2, _injection_thread
    mov     x3, xzr
    adr     x8, _pthread_create_sym
    ldur    x16, [x8]
    blr     x16
    b       _injection_loop

_injection_thread:
    sub     sp, sp, #0x20
    stp     x29, x30, [sp, #0x10]
    add     x29, sp, #0x10
    adr     x0, _dylib_path
    movz    x1, #0x1
    adr     x8, _dlopen_sym
    ldur    x16, [x8]
    blr     x16
    ldp     x29, x30, [sp, #0x10]
    add     sp, sp, #0x20
    ret

_injection_loop:
    b       _injection_loop

_pthread_create_sym:    .quad 0x4141414141414141
_dlopen_sym:            .quad 0x4242424242424242
_dylib_path:            .space 1024

_padding:
    .rept 1000
    nop
    .endr
