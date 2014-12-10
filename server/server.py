#!/usr/bin/env python2.7

import json
import time
import socket
import threading
import SocketServer
from encrypt import *
from Crypto.PublicKey import RSA
from server_helper import *

# Server socket parameters
buffer_size = 1024
host = "localhost"
servername = "efs-server"
port = 1025

use_threaded = False
efs_server = None


# Crypto parameters
RSA_KEY_SIZE = 2048

class EFSServer:

	key = None # Server's RSA public/private key pair
	users = None
	files = None

	def __init__(self):
		self.key = RSA.generate(RSA_KEY_SIZE)
		self.users = {}
		self.files = {}

	def handle_request(self, req):
		print "I am supposed to handle:", str(req)

		try:
			handler = req["data"]["action"]
			username = req["username"]
			data = req["data"]
			signature = req["signature"]

			# INITAL FUNCTIONS
			if handler == "register":
				# rebuild user public key
				pub = req["data"]["public_key"]
				N = long(pub["N"])
				e = long(pub["e"])
				rsa_pub = RSA.construct((N, e))
				acl = data["acl"]

				if verify_inner_dictionary(rsa_pub, signature, data):
					print "Signature verfied. Registering user..."
					resp = self.register(username, rsa_pub, acl)
					return resp
			elif handler == "key":
				pub = self.key.publickey()
				okmsg = "Sending Server Key"
				print okmsg
				resp = OKResponse(okmsg)
				return resp.getPayload({"public_key":{"N":pub.n, "e": pub.e}})

			# FILE FUNCTIONS (1)
			elif handler == "create":
				if verify_inner_signature(self.users[username], signature, data):
					print "Signature verfied. Creating file..."
					resp = self.create(username, data["filename"], data["file"], data["acl"])
					#TO DO


			elif handler == "delete":
				print "Not implemented.."

			#(2)	
			elif handler == "read":
				print "Not implemented.."

			#(3)
			elif handler == "write":
				print "Not implemented.."

			elif handler == "rename":
				print "Not implemented.."

			# DIRECTORY FUNCTIONS
			#(4)
			elif handler == "mkdir":
				print "Not implemented.."

			elif handler == "remove":
				print "Not implemented.."

			elif handler == "ls":
				print "Not implemented.."

			elif handler == "cd":
				print "Not implemented.."


		except KeyError as ke:
			print "Couldn't find expected action. Please use --help to see possible commands."

	
	def register(self, username, pub_key, acl):
		if username in self.users:
			errmsg = "User %s already exists" % username
			return ErrorResponse(errmsg)

		u = UserEntry(username, pub_key)
		self.users[username] = u
		self.files[username] = {}
		okmsg = "Added user %s" % str(u)
		print okmsg
		data = {}
		resp = OKResponse(okmsg)
		return resp.getPayload(data)

	def create(self, username, filename, file, acl):
		if username not in self.users:
			errmsg =  "User %s not registered" % username
			return ErrorResponse(errmsg)

		#create file in sub directory
		if len(filename) > 1:
			#creating file in other directories, so path is [uname, path1, path2, fn]
			if filename[0] is username:
				

			# creating file in own directory at supplied path [path1, path2, fn]
			else:
				if 

		
		# creating file in user home directory so just [fn]
		else:


		

		#My code here.


class ACL:
	filename = None
	table = None
	signature = None

	ACL_READ = 0
	ACL_WRITE = 1

	def __init__(self, filename):
		self.filename = filename
		self.table = {}
		self.signature = None

	def is_valid(self, key):
		if self.signature is None:
			return False

		representation = {"filename": self.filename, "table": self.table}
		return verify_inner_dictionary(key, self.signature, representation)

	def set_signature(self, signature):
		self.signature = signature

	def set_table(self, table):
		self.table = table

	def is_readable(self, user):
		return self.table[user][ACL_READ] == "1"

	def is_writable(self, user):
		return self.table[user][ACL_WRITE] == "1"


class EFSHandler(SocketServer.BaseRequestHandler):
	def handle(self):
		data = self.request.recv(buffer_size)
		if use_threaded:
			cur_thread = threading.current_thread()
			response = "{} responds, {}".format(cur_thread.name, data)
		else:
			response = "Server responds: {}".format(data)
		efs_server.handle_request(data)
		self.request.sendall(response)

if __name__ == "__main__":
	efs_server = EFSServer()

	if use_threaded:
		server = SocketServer.ThreadingTCPServer((host, port), EFSHandler)

		server_thread = threading.Thread(target=server.serve_forever, name=servername)
		server_thread.daemon = True
		server_thread.start()
	else:
		server = SocketServer.TCPServer((host, port), EFSHandler)

	print "Server is running..."

	try:
		server.serve_forever()
	except KeyboardInterrupt as ki:
		print "Keyboard interrupt"
		server.shutdown()



