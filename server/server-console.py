#!/usr/bin/env python2.7

import socket
import json
import re

from Crypto.PublicKey import RSA

HOST = 'localhost'
PORT = 1026

server_public = None

user_name = ""
user_rsa = None

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.settimeout(1)

helptext = """	register - register a user
	get server key - get server's public key
	print server key - print server's public key
	print user key - print user's RSA key
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

	elif cmd == "who am i":
		print "[who am i] %s" % user_name

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
	print "whoops,", e
finally:
	s.close()
