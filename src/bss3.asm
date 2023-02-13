global _start
section .text

_start:
mov rax, zero
xor rdi, rdi
mov rax, 60
syscall

section .bss

pad: resq 65536
zero: resq 16
