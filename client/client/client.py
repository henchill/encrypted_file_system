import socket
import cPickle as pickle
from client_objects import *
from Crypto.PublicKey import RSA
import Crypto.Random as random

CURRENT_USER = None
HOST = ''
PORT = 1026
SERVER_PK = None

def register(username):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    msg = Message('newUser', None, None, None, None)
    s.connect((HOST, PORT))
    
    # obtain dh prime and base, and server public key
    s.send(pickle.dumps(msg))
    resp = pickle.loads(s.recv(4096)).getData()

    # store server public key locally
    dh_secret = random.get_random_bytes(128)
    
    # create current user
    CURRENT_SESSION = Session(username, RSA.generate(2048), dh_secret,
                           resp['prime'], resp['base'], resp['public_key')
    
    data = {
    	'username': CURRENT_SESSION.username,
    	'action': 'registerUser',
    	'dh_value': dh_power(),
    	'public_key': CURRENT_SESSION.key.publickey()
    }
    
    msg = createEncryptedMessage(CURRENT_SESSION, SERVER_PK, data)
    s.send(msg)
    resp = pickle.loads(s.recv(4096))
    if (resp.status == "OK"):
    	return 'Successfully created account for %s' % username
    return 'Could not register %s' % username


def sign_in(username):
    CURRENT_USER = User(username)
    
def createFile(name):
    raise NotImplementedError

def createFolder(name):
    raise NotImplementedError

def deleteFile(name):
    raise NotImplementedError

def deleteFolder(name):
    raise NotImplementedError

def dh_power():
    """
    Borrowed from http://stackoverflow.com/a/16421707
    """
    a, p_mod, g_base = CURRENT_SESSION.dh_key
    x = 1
      bits = "{0:b}".format(a)
      for i, bit in enumerate(bits):
        if bit == '1': 
        	x = (((x**2)*g_base)%p_mod)
        elif bit == '0': 
        	x = ((x**2)%p_mod)
      return x % p_mod