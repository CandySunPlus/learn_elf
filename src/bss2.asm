global _start
section .text

_start:
lea rax, [rel zero]
mov rax, [rax]
xor rdi, rdi
mov rax, 60
syscall

section .bss

pad: resq 65536
zero: resq 16
