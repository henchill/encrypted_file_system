#!/usr/bin/env python2.7

import base64
import socket
import json
import re
import client

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto import Random

# Server things
HOST = 'localhost'
PORT = 1027

server_public = None

# User-specific
current_user = None

# Encryption details
chunk_size = 200

# Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.settimeout(1)

helptext = """ Coming Soon	"""

def dispatch(cmd, args):
	global current_directory, server_public, current_user

	# REGISTER
	if cmd == "register":
		if len(args) > 1:
			print "Please specify a proper username. Username cannot contain spaces."
		elif (len(args) == 0):
			print "Please specify a username"
		else:
			resp, server_public, current_user = client.register(s, args[0])
			if resp['status'] == 'error': 
				print "Failed to register user. %s" % resp['message']
			else:
				print "Account created. Welcome, %s" % current_user.username


try:
	while True:
		try:
			user_input = raw_input("tefs> ")
			cmd = user_input.split(' ')[0]
			args = user_input.split(' ')[1:]
			if cmd == "quit":
				print "Bye"
				break
			else:
				dispatch(cmd, args)
		except socket.timeout as st:
			print "(socket) timeout"
			continue
		except (ValueError, KeyboardInterrupt) as e:
			print e
			continue
except EOFError as e:
	print "\nBye"
except Exception as e:
	raise
finally:
	s.close()
