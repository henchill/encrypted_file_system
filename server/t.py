from transmit import EFSConnection
from Crypto.PublicKey import RSA

k = RSA.generate(2048)

def t():
	with EFSConnection("localhost", 1025) as c:
		c.transmit(k, "hellogoodbye")

def tt():
	with EFSConnection("localhost", 1025) as c:
		c.transmit(k, "hellogoodbye" * 40)
