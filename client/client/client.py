import socket
import cPickle as pickle
from message import *

USERNAME = None
HOST = ''
PORT = 1026
DH_SECRET = None
DH_PRIME = None
DH_BASE = None

def register(username):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	createUserMsg = Message(username, 'createUser', None, None, None)
	s.connect((HOST, PORT))
	# obtain prime and base from server
	s.send(pickle.dumps(msg))
	resp = pickle.loads(s.recv(4096))

	DH_PRIME = resp.prime
	DH_BASE = resp.base
	DH_SECRET = random.getrandbits(128)

	storeDHMsg = Message(username, 'registerUser', )

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