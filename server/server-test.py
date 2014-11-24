#!/usr/bin/env python2.7

import socket
import sys
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
import base64
import re

HOST = 'localhost'
PORT = 1028

use_socket = True

# Key generation
key = RSA.generate(2048)
pub = key.publickey()

# Socket creation
if use_socket:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((HOST, PORT))

# Registration information
registration = "register Alice %ld %ld" % (0, pub.e)

# Register
pub_N = 0
pub_e = 0
print "I sent", registration
if use_socket:
	s.sendall(registration)
	data = s.recv(1024)
	print "In response to registration, I got", data
	data = s.recv(1024)
	print "Then, I got", data
	pub_tuple = re.match(r"OK \((\d+), (\d+)\)", data)
	if pub_tuple is not None:
		pub_N = long(pub_tuple.group(1))
		pub_e = long(pub_tuple.group(2))
		print "Server public key is (%lu, %lu)" % (pub_N, pub_e)

server_public = RSA.construct((pub_N, pub_e))

# Create test message
message = "hello bob"
message_fn = "hello.txt"

h = SHA.new(message)
hfn = SHA.new(message_fn)

cipher = PKCS1_v1_5.new(key)
ciphertext = cipher.encrypt(message + h.digest())
ciphertext_fn = cipher.encrypt(message_fn + hfn.digest())

b64c = base64.b64encode(ciphertext)
b64cfn = base64.b64encode(ciphertext_fn)

# Creation
creation = "create Alice %s %s" % (b64c, b64cfn)
creation_h = SHA.new(creation)

print "creation is", creation

server_cipher = PKCS1_v1_5.new(server_public)
ciphertext_creation = cipher.encrypt(creation + creation_h.digest())

print "I sent", creation
print "(Encrypted:", ciphertext_creation, ")"
if use_socket:
	s.sendall(creation)
	data = s.recv(1024)
	print "In response to create, I got", data

if use_socket:
	s.close()
