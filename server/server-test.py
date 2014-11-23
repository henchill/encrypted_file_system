#!/usr/bin/env python2.7

import socket
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA

HOST = 'localhost'
PORT = 1027

# Key generation
key = RSA.generate(2048)
pub = key.publickey

# Socket creation
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

# Registration information
registration = "register Alice %ld %ld" % (0, pub.e)

# Register
s.sendall(registration)
data = s.recv(1024)
print "In response to registration, I got", data
data = s.recv(1024)
print "Then, I got", data

sys.exit()

# Create test message
message = "hello bob"
message_fn = "hello.txt"
h = SHA.new(message)

cipher = PKCS1_v1_5.new(key)
ciphertext = cipher.encrypt(message + h.digest())

# Creation
creation = "create Alice " + ciphertext
s.sendall(creation)
data = s.recv(1024)
print "In response to create, I got", data

s.close()
