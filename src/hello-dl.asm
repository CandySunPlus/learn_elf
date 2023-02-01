global _start
extern msg
section .text

_start:
mov rdi, 1
mov rsi, msg
mov rdx, 9
mov rax, 1
syscall

xor rdi, rdi
mov rax, 60
syscall
