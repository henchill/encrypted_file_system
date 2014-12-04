import socket as sock_conn
import json
import base64

from client_objects import *
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from transceive import *
from encrypt import *

def register(socket, username):
	current_user = User(username, RSA.generate(2048))
	data = base64.b64encode(json.dumps({
		'username': username,
		'action': 'register',
		'public_key': current_user.get_public_key()
	}))

	signature = current_user.sign(data)

	msg = base64.b64encode(json.dumps({
		'username': username,
		'signature': signature,
		'data': data
	}))

	s.send(msg) #send unencrypted msg 
	resp = s.recv(1024) #receive server resp
	print resp
	#server_public = resppublic_key
	

	

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
