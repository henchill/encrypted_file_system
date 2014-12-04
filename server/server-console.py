#!/usr/bin/env python2.7

import base64
import socket
import json
import re

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto import Random

# Server things
HOST = 'localhost'
PORT = 1027

server_public = None

# User-specific
user_name = ""
user_rsa = None

# Encryption details
chunk_size = 200

# Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.settimeout(1)

helptext = """	register - register a user

	get server key - get server's public key
	print server key - print server's public key
	print user key - print user's RSA key

	create - create an empty file on server
	write - write to encrypted file on server
	read - read from encrypted file on server

	encrypt - send encrypted message to server

	who am i - print name you're acting as
	help - this help message
	quit - quit"""

def dispatch(cmd):
	global server_public, user_rsa, user_name

	# REGISTER
	if cmd == "register":
		name = raw_input("[register] name> ")
		dh   = raw_input("[register] dh key> ")
		pub  = raw_input("[register] pub key> ")

		if pub == "generate":
			user_rsa = RSA.generate(2048)
			N = user_rsa.n
			e = user_rsa.e
			user_name = name
		else:
			user_tuple = re.match(r"\((\d+), (\d+)\)", pub)
			if user_tuple is not None:
				N = long(user_tuple.group(1))
				e = long(user_tuple.group(2))
				user_rsa = RSA.construct((N, e))
				user_name = name
			else:
				raise ValueError("must be \"generate\" or of format (N, e)")

		request = {"action": "register", "name": name, "dh": dh, "pub": {"N": N, "e": e}}
		print request
		request_str = json.dumps(request)
		s.sendall(request_str)

		data = s.recv(1024) # "Got register"
		print "(server)", data

	# GET SERVER KEY
	elif cmd == "get server key":
		request = {"action": "key"}
		request_str = json.dumps(request)
		s.sendall(request_str)

		data = s.recv(1024) # "(N, e)"
		print "(server)", data

		server_tuple = re.match(r"OK \((\d+), (\d+)\)", data)
		if server_tuple is not None:
			N = long(server_tuple.group(1))
			e = long(server_tuple.group(2))
			server_public = RSA.construct((N, e))

	# PRINT USER KEY
	elif cmd == "print user key":
		if user_rsa is not None:
			print "[print user key] user: %s has key (%lu, %lu)" % (user_name, user_rsa.n, user_rsa.e)
		else:
			print "[print user key] don't have one generated yet"

	# PRINT SERVER KEY
	elif cmd == "print server key":
		if server_public is not None:
			print "[print server key] (%lu, %lu)" % (server_public.n, server_public.e)
		else:
			print "[print server key] don't know the key"

	# WHO AM I
	elif cmd == "who am i":
		print "[who am i] %s" % user_name

	# ENCRYPT
	elif cmd == "encrypt":
		if server_public is None:
			print "[encrypt] get the server key first"
			return
		msg = raw_input("[encrypt] message> ")
		cipher = PKCS1_OAEP.new(server_public)
		ciphertexts = []
		for start in xrange(0, len(msg), chunk_size):
			end = start + chunk_size
			chunk = msg[start:end]
			ciphertexts.append(base64.b64encode(cipher.encrypt(chunk)))

		request = {"action": "decrypt", "ciphertexts": ciphertexts}
		request_str = json.dumps(request)
		print request_str
		s.sendall(request_str)
		
	# CREATE
	elif cmd == "create":
		if user_rsa is None or user_name is "":
			print "[create] generate user name and key using \"register\""
		else:
			filename = raw_input("[create] filename> ")
			cipher = PKCS1_OAEP.new(user_rsa)
			ciphertext = user_rsa.encrypt(filename, 0)[0]
			ciphertext_encoded = base64.b64encode(ciphertext)
			request = {"action": "create", "user": user_name, "filename": ciphertext_encoded}
			request_str = json.dumps(request)
			s.sendall(request_str)

			data = s.recv(1024) # Created file ...
			print "(server)", data

	# WRITE
	elif cmd == "write":
		if user_rsa is None or user_name is "":
			print "[write] generate user name and key using \"register\""
			return

		filename = raw_input("[write] filename> ")
		# Must not pad filename (at least, not with random bytes)
		filename_ciphertext = user_rsa.encrypt(filename, 0)[0]
		filename_ciphertext_encoded = base64.b64encode(filename_ciphertext)

		contents = raw_input("[write] contents> ")
		length = len(contents)
		cipher = PKCS1_OAEP.new(user_rsa)
		chunks = length / chunk_size + 1

		for seq in xrange(0, chunks):
			start = seq * chunk_size
			end = start + chunk_size
			chunk = contents[start:end]
			chunk_ciphertext = base64.b64encode(cipher.encrypt(chunk))
			request = {"action": "write", "filename": filename_ciphertext_encoded, "length": length, "seq": seq, "blob": chunk_ciphertext}
			request_str = json.dumps(request)
			print request_str

			s.sendall(request_str)
			data = s.recv(1024) # File ... (#/#)
			print "(server)", data

	# READ
	elif cmd == "read":
		if user_rsa is None or user_name is "":
			print "[write] generate user name and key using \"register\""
			return

		filename = raw_input("[read] filename> ")
		# Must not pad filename (at least, not with random bytes)
		filename_ciphertext = user_rsa.encrypt(filename, 0)[0]
		filename_ciphertext_encoded = base64.b64encode(filename_ciphertext)

		blobs = []

		# Get first chunk, that has the length
		request = {"action": "read", "filename": filename_ciphertext_encoded, "seq": 0}
		request_str = json.dumps(request)
		print request_str

		s.sendall(request_str)
		data = s.recv(1024) # OK {..}
		print "(server)", data

		response = json.loads(data)
		if response["response"] != "OK":
			return

		chunk = response["chunk"]

		# Do we have more? Bring in other chunks.
		length = response["length"]
		chunks = length / chunk_size + 1
		if chunks > 1:
			blobs = [None] * chunks
			blobs[0] = chunk

			for seq in xrange(1, chunks):
				request = {"action": "read", "filename": filename_ciphertext_encoded, "seq": seq}
				request_str = json.dumps(request)
				print request_str

				s.sendall(request_str)
				data = s.recv(1024) # { .. }
				print "(server)", data

				response = json.loads(data)
				if response["response"] == "OK":
					chunk = response["chunk"]
					blobs[seq] = chunk
		else:
			blobs = [chunk]

		# Decrypt
		plaintext = ""

		cipher = PKCS1_OAEP.new(user_rsa)
		for blob in blobs:
			chunk_plaintext = cipher.decrypt(base64.b64decode(blob))
			plaintext += chunk_plaintext

		print "[read] plaintext:\n" + plaintext

	# HELP
	elif cmd == "help":
		print helptext

try:
	while True:
		try:
			cmd = raw_input("tefs> ")
			if cmd == "quit":
				print "Bye"
				break
			else:
				dispatch(cmd)
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
