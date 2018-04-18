
with open('morse2','r') as f:
    a = [x.strip() for x in f.readlines()]


ut = ''

for c in a:
    ut += str(c[-2:])

print ut

#Morse som gir:
#
#15_W45_D4_53C0ND_0H
