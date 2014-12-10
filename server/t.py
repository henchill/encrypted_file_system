from transmit import EFSConnection
from Crypto.PublicKey import RSA

k = RSA.importKey(open("server.key"))

def t():
	with EFSConnection("localhost", 1025) as c:
		c.transmit(k, "hellogoodbye")

def tt():
	with EFSConnection("localhost", 1025) as c:
		c.transmit(k, "hellogoodbye" * 40)
