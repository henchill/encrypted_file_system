import socket
import cPickle as pickle
from client_objects import *
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

CURRENT_USER = None
HOST = ''
PORT = 1026
SERVER_PUBLIC_KEY = None

def register(username):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	newUserMsg = Message('newUser', None, None, None, None)
	s.connect((HOST, PORT))
	# obtain dh prime and base, and server public key
	s.send(pickle.dumps(msg))
	resp = pickle.loads(s.recv(4096))

	SERVER_PUBLIC_KEY = resp.public_key
	CURRENT_USER = User(username)
	dh_prime = resp.prime
	dh_base = resp.base
	dh_secret = random.getrandbits(128)

	CURRENT_USER.add_dh_key(dh_secret, dh_prime, dh_base)
	CURRENT_USER.add_rsa_key(RSA.generate(2048))
	data = pickle.dumps({
		'username': CURRENT_USER.username,
		'action': 'registerUser',
		'dh_value': power(dh_base, dh_secret, dh_prime),
		'public_key': CURRENT_USER.key.publicKey()
	})
	signature = CURRENT_USER.key.sign(data)
	storeDHMsg = Message(CURRENT_USER.username, data, signature)
	s.send(pickle.dumbs(CURRENT_USER.key.encrypt(pickle.dumps(storeDHMsg))))
	resp = pickle.loads(s.recv(4096))
	if (resp.status == "OK"):
		return True
	return False


def createFile(name):
	raise NotImplementedError

def createFolder(name):
	raise NotImplementedError

def deleteFile(name):
	raise NotImplementedError

def deleteFolder(name):
	raise NotImplementedError

def power(g_base, a, p_mod):
	"""
	Borrowed from http://stackoverflow.com/a/16421707
	"""
	x = 1
  	bits = "{0:b}".format(a)
  	for i, bit in enumerate(bits):
	    if bit == '1': 
    		x = (((x**2)*g_base)%p_mod)
    	elif bit == '0': 
    		x = ((x**2)%p_mod)
  	return x % p_mod