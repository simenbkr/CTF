with open('out', 'r') as f:
    packets = [x.strip('\n') for x in f.readlines()]

p = []
for packet in packets:
    size = (int(packet[:8], 16))
    seq = (int(packet[8:16], 16))
    data = packet[16:]

    p.append([size,seq,data])



s = sorted(p, key=lambda x: x[1])
data = ''

for a in s:
    data += a[2]

print data.decode("hex")
