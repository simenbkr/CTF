
"""
mem = {1:1}
def thingy(a):
    if a in mem:
        return mem[a]
    if a == 1:
        return 1
    mem[a] = thingy(a-1) + thingy(a-2)
    return mem[a]
"""
from math import floor, sqrt

def thingy(n):
    return int(floor(((1+sqrt(5))**n-(1-sqrt(5))**n)/(2**n*sqrt(5))+0.5))


hmm = "4E,42,52,41,32,3D,73,7D,67,11,2,6C,CF,8F,26,55,EB,62,68,61,14,9D,5D,C2,15,61,2,21,44,80,55"

hmm = hmm.split(',')
hmm = [int(i, 16) for i in hmm]

print hmm

ut = ''

for i in range(len(hmm)):
    ut += chr( (hmm[i] ^ thingy(i) ) % 256)

print ut



