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

root = 'root'
# Crypto parameters
RSA_KEY_SIZE = 2048

class EFSServer:

	key = None # Server's RSA public/private key pair
	users = None
	files = None

	def __init__(self):
		self.key = RSA.generate(RSA_KEY_SIZE)
		self.users = {}
		self.files = []
		self.home_acls = {}

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
				acl_signature = data["signature_acl"]

				if verify_inner_dictionary(rsa_pub, signature, data):
					print "Signature verfied. Registering user..."
					resp = self.register(username, rsa_pub, acl, acl_signature)
					return resp
			elif handler == "key":
				pub = self.key.publickey()
				okmsg = "Sending Server Key"
				for user in users:
					if username == user.name:
						pub = user.public_key
						okmsg = "Sending public key of user %s" % username

				print okmsg
				resp = OKResponse(okmsg)
				return resp.getPayload({"public_key":{"N":pub.n, "e": pub.e}})

			# FILE FUNCTIONS (1)
			elif handler == "create":
				if verify_inner_signature(self.users[username], signature, data):
					print "Signature verfied. Creating file..."
					resp = self.create(username, data["filename"], data["file"], data["acl"])
					return resp

			elif handler == "delete":
				print "Not implemented.."

			#(2)	
			elif handler == "read":
				if verify_inner_dictionary(self.users[username], signature, data):
					print "Signature verfied. Trying to read file..."
					resp = self.read(username, data["filename"])
					return resp
		
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

	
	def register(self, username, pub_key, table, signature):
		if username in self.users:
			errmsg = "User %s already exists" % username
			return ErrorResponse(errmsg)

		u = UserEntry(username, pub_key)
		self.users[username] = u
		okmsg = "Added user %s" % str(u)
		print okmsg
		self.home_acls{username} = ACL(username, table, signature)
		home_dir = DirEntry(username, username, {}, [])
		self.files.append(home_dir)
		filemsg = "Added home directory for user %s" % str(username)
		print filemsg
		data = {}
		resp = OKResponse(okmsg)
		return resp.getPayload(data)

	def create(self, username, filename, file_content, file_acl):
		if username not in self.users:
			errmsg =  "User %s not registered" % username
			return ErrorResponse(errmsg)
		(perm, msg, parent) = self.traverse(username, filename)
		data = {}
		if perm:	
			#Made it here => can create file in parent
			fe = FileEntry(filename, username, file_acl, file_content)
			current_dir.add_file(fe)
			createmsg = "File created with filename %s" % str(filename)
			print createmsg
			resp = OKResponse(createmsg)
			return resp.getPayload(data)
		else:
			print msg
			resp = ErrorResponse(msg)
			return resp.getPayload(data)	

	def read(self, username, filename):
		if username not in self.users:
			errmsg =  "User %s not registered" % username
			return ErrorResponse(errmsg)
		(perm, msg, parent) = self.traverse(username, filename)
		data = {}
		if perm:	
			#Made it here => can read file in parent
			fe = parent.get_entry(filename)
			if fe.is_readable(username):
				data["filename"] = filename
				data["file"] = fe.get_file()
				data["acl"] = fe.get_acl()
			readmsg = "Sending file for Read with filename %s" % str(filename)
			print readmsg
			resp = OKResponse(readmsg)
			return resp.getPayload(data)
		else:
			print msg
			resp = ErrorResponse(msg)
			return resp.getPayload(data)

	def traverse(self, username, filename):
		fn = filename
		current_dir = None

		# if creating in own dir, add uname
		if (filename[0] not in self.users):
			fn.insert(0,username)
			
		while (len(fn)>1):
			current_name = fn.pop(0)
			if (current_name in self.users):
				home_acl = self.home_acls[current_name]
				if (home_acl.is_readable(username) == False):
					errmsg =  "Permission denied %s" % current_name
					return (False, errmsg)
				else:
					for e in self.files:
						if e.name == username:
							current_dir = e
					continue
			else:
				current_acl = current_dir.get_acl()[current_name]
				if (current_acl.is_readable(username) == False):
					errmsg =  "Permission denied %s" % current_name
					return (False, errmsg)
				else:
					current_dir = current_dir.get_entry(current_name)
					continue
		okmsg = "User has sufficient permissions.."
		return (True, okmsg, current_dir)

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



