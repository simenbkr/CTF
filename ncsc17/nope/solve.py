


a = "cuIE_FNuOREXONu^BOu]BEFOuNKSuFEDM"

s = ''


for char in a:
    s += chr(ord(char) ^ 0x2a)


print s






