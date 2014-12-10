#!/usr/bin/env python2.7

from transmit import EFSConnection
from Crypto.PublicKey import RSA
from Crypto import Random
from encrypt import *

import os
import sys
import time
import json
import socket

port = 1025
host = "localhost"

def client():
	with EFSConnection(host, port) as c:
		# Test making connection, transmitting
		test = 6
		c.transmit_encrypted(k, "hello")
		print "TEST %d: PASS" % test

		# Test receiving stuff
		test = 8
		data = c.receive(1024)

		if data == "hi again":
			print "TEST %d: PASS" % test
		else:
			print "TEST %d: FAIL" % test

	os._exit(0)

try:
	# Test key generation
	test = 0
	k = RSA.generate(2048)
	print "TEST %d: PASS" % test

	# Test making server socket
	test = 1
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind((host, port))
	s.listen(2)
	print "TEST %d: PASS" % test

	newpid = os.fork()
	Random.atfork()
	if newpid == 0:
		time.sleep(2)
		client()

	# Test accepting connection
	test = 3
	conn, addr = s.accept()
	print "TEST %d: PASS" % test

	# Test receiving short string
	test = 4
	data = conn.recv(1024)
	if data is None or data == "":
		print "TEST %d: FAIL" % test
	else:
		print "TEST %d: PASS" % test
		# print data

	# Test decryption
	test = 5
	d = json.loads(data)
	plaintext = decrypt(k, [d["payload"]])
	if plaintext == "hello":
		print "TEST %d: PASS" % test
	else:
		print "TEST %d: FAIL" % test

	time.sleep(2)

	# Test sending response
	test = 7
	conn.sendall("hi again")
	print "TEST %d: PASS" % test

	s.close()

except Exception as e:
	print "TEST %d: EXCEPTION: %s" % (test, str(e))
	sys.exit(1)
finally:
	s.close()
