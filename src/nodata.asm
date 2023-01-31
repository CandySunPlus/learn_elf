; in `hello.asm`
; nasm -f elf64 hello.asm
; mold hello.o -o hello

        global _start

        section .text

_start: mov rdi, 1      ; stdout fd
        sub rsp, 10
        mov byte [rsp+0], 111
        mov byte [rsp+1], 107
        mov byte [rsp+2], 97
        mov byte [rsp+3], 121
        mov byte [rsp+4], 32
        mov byte [rsp+5], 116
        mov byte [rsp+6], 104
        mov byte [rsp+7], 101
        mov byte [rsp+8], 110
        mov byte [rsp+9], 10
        mov rsi, rsp

        mov rdx, 10      ; 8 chars + newline
        mov rax, 1      ; write syscall
        syscall
        add rsp, 10

        xor rdi, rdi    ; return code 0
        mov rax, 60     ; exit syscall
        syscall
        
