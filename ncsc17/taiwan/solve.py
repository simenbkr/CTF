
N_bob = 86987754719664230158310981665063255536413046790233761847450960688472522608895086474402869393290110233867826048268546028232697993941324914269279980713934550428186651488483325044101840135539559527511167503386523860625610303543312093217797066599891048842930708576256789217904010179326839630485691278069683634737L

N_alice = 71105252524281280263011020784363568621401478330082408983279047354494225388318254558567128980104957353135879490341441380438684835791600769084197771145499474945594229816896772190549770029852216520660015182698267741791689323403315888127961165962358676714779130828084734909872730879174658699508050643067630563533L



felles_p = 10772399014635047233590315990509476308691490562115716645852505067548645065380425045219592726097566811241932355481605775875329870322201648295675535129493661

from Crypto.Util.number import *

def extended_gcd(aa, bb):
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient*x, x
        y, lasty = lasty - quotient*y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)

def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError
    return x % m


def modexp ( g, u, p ):
   s = 1
   while u != 0:
      if u & 1:
         s = (s * g)%p
      u >>= 1
      g = (g * g)%p;

   return s


alice_q = N_alice/felles_p
bob_q = N_bob/felles_p
q = alice_q
p = felles_p

print "AliceQ:{}\nP:{}\nBobQ:{}".format(q, p, bob_q)

assert p*q == N_alice
assert p*bob_q == N_bob

phi = (p-1)*(q-1)

e = 65537

alice_d = modinv(e, phi)
bob_d = modinv(e, (p-1)*(bob_q-1))

print( "Alice_d: {}\nBob_d: {}".format(alice_d, bob_d))
with open('Ciphertext.txt','r') as f:
    c = f.read()


c ='@\n\xea\xa9\xd9C6\xfd]{:\xaf\xe0\xf6\xe3\x15\xb7\x92i\x0e}\x7f\x8c\xc5\xa9q\xcb\x94\xac{\xad\x0bU\xf5\x8b\xfe\xfbd\xa2\x8e\x19\xa0\xddN\xbb\xfc\xb3W\xcez\xa3\x17\xa8U\n\xf4\xda\xc4\xe1\xa1x"Gw\x00\x12\xd9`;\n\x0c\x94\xef\xe8S\xcd\xa8\x91\xb6\xf08\xeb\n\x8d\xa9u\xec]\xd8\xeb\x98\xf7\x9c\xdbW\xe1h}h\x92\x0f\xa0\x8d\xd8\x0c\x978\xe6\xf7\xc5\xdb\xaa\xca\xf1P\xbf\x1e5\xba\x9f\rc\x92CB\x1eX\x84'



ciph = bytes_to_long(c)
dec = modexp(ciph ,alice_d,N_alice)

print(long_to_bytes(dec))



