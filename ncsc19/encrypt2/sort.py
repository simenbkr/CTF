with open('flag.enc', 'rb') as f:
    content = f.read()

salt, enc = content.split(chr(36))

with open('salt', 'w') as f:
    f.write(salt)

with open('enc', 'w') as f:
    f.write(enc)
