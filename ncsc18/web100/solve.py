
from django.core.signing import Signer
SECRET_KEY = '6bk^r*93y$^fg#lzq_87(_4ig^u*j0f%^-x_6j==wi9w8p$ru9'

signer = Signer(SECRET_KEY)

print signer.sign(1)


