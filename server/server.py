#!/usr/bin/env python2.7

import json
import time
import socket
import threading
import SocketServer
from encrypt import *
from Crypto.PublicKey import RSA
from server_helper import *

import traceback

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
		# print "I am supposed to handle:", str(req)

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
				else:
					errmsg = "Signature verification failed, could not register."
					print errmsg

			elif handler == "key":
				pub = self.key.publickey()
				okmsg = "Sending Server Key"
				if username in self.users:
					pub = self.users[username].public_key
					okmsg = "Sending public key of user %s" % username
				else:
					resp = ErrorResponse("No user name %s exists" % username)

				print okmsg
				resp = OKResponse(okmsg)
				return resp.getPayload({"public_key":{"N":pub.n, "e": pub.e}})

			# FILE FUNCTIONS
			elif handler == "create":
				user_pub = self.users[username].public_key
				if verify_inner_dictionary(user_pub, signature, data):
					print "Signature verfied. Creating file..."
					resp = self.create(username, data["filename"], data["file"], data["acl"], data["signature_acl"])
					return resp

			elif handler == "delete":
				user_pub = self.users[username].public_key
				if verify_inner_dictionary(user_pub, signature, data):
					print "Signature verfied. Trying to fetch file for read request..."
					resp = self.delete_file(username, data["filename"])
					return resp
		
	
			elif handler == "read":
				user_pub = self.users[username].public_key
				if verify_inner_dictionary(user_pub, signature, data):
					print "Signature verfied. Trying to fetch file for read request..."
					resp = self.read(username, data["filename"])
					return resp
		
			elif handler == "write":
				user_pub = self.users[username].public_key
				if verify_inner_dictionary(user_pub, signature, data):
					print "Signature verfied. Trying to fetch file for write request..."
					resp = self.write(username, data["filename"], data["file"])
					return resp

			elif handler == "rename":
				print "Not implemented.."

			# DIRECTORY FUNCTIONS
			elif handler == "mkdir":
				if verify_inner_dictionary(self.users[username], signature, data):
					print "Signature verfied. Trying to create directory..."
					resp = self.mkdir(username, data["dirname"], data["acl"], data["signature_acl"])
					return resp

			elif handler == "remove":
				if verify_inner_dictionary(self.users[username], signature, data):
					print "Signature verfied. Trying to create directory..."
					resp = self.delete_dir(username, data["dirname"])
					return resp

			elif handler == "ls":
				if verify_inner_dictionary(self.users[username], signature, data):
					print "Signature verfied. Trying to create directory..."
					resp = self.list_contents(username, data["dirname"], data["acl"], data["signature_acl"])
					return resp

		except KeyError as ke:
			print "Couldn't find expected action. Please use --help to see possible commands."
			print ke
			print traceback.format_exc()

	
	def register(self, username, pub_key, table, acl_signature):
		if username in self.users:
			errmsg = "User %s already exists" % username
			return ErrorResponse(errmsg)

		u = UserEntry(username, pub_key)
		self.users[username] = u
		okmsg = "Added user %s" % str(u)
		print okmsg
		self.home_acls[username] = ACL(username, table, acl_signature)
		home_dir = DirEntry(username, username, {}, [])
		self.files.append(home_dir)
		filemsg = "Added home directory for user %s" % str(username)
		print filemsg
		data = {}
		resp = OKResponse(okmsg)
		return resp.getPayload(data)

	def create(self, username, filename, file_content, file_acl, signature_acl):
		if username not in self.users:
			errmsg =  "User %s not registered" % username
			return ErrorResponse(errmsg)
		(perm, msg, parent) = self.traverse(username, filename)
		data = {}
		if perm:	
			#Made it here => can create file in parent
			acl = ACL(filename, signature_acl, file_acl)
			fe = FileEntry(filename, username, acl, file_content)
			parent.add_file(fe)
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
				data["file"] = fe.get_contents()
				readmsg = "Sending file for Read with filename %s" % str(filename)
				print readmsg
				resp = OKResponse(readmsg)
				return resp.getPayload(data)
		else:
			print msg
			resp = ErrorResponse(msg)
			return resp.getPayload(data)

	def write(self, username, filename, file_contents):
		if username not in self.users:
			errmsg =  "User %s not registered" % username
			return ErrorResponse(errmsg)
		(perm, msg, parent) = self.traverse(username, filename)
		data = {}
		if perm:	
			#Made it here => can write file in parent
			fe = parent.get_entry(filename)
			if fe.is_writable(username):
				fe.set_contents(file_contents)
				writemsg = "Writing to file complete for filename %s" % str(filename)
				print writemsg
				resp = OKResponse(writemsg)
				return resp.getPayload(data)
		else:
			print msg
			resp = ErrorResponse(msg)
			return resp.getPayload(data)


	def mkdir(self, username, dirname, dir_acl, signature_acl):
		if username not in self.users:
			errmsg =  "User %s not registered" % username
			return ErrorResponse(errmsg)
		data = {}
		if (len(dirname) == 1):
			for home_e in self.files:
				if home_e.name = username:
					parent = home_e
					acl = ACL(dirname, signature_acl, dir_acl)
					de = DirEntry(dirname, username, {}, [])
					parent.add_dir(dirname, de, acl)
					mkdirmsg = "Created directory with dirname %s" % str(dirname)
					print mkdirmsg
					resp = OKResponse(mkdirmsg)
					return resp.getPayload(data)

		(perm, msg, grandparent) = self.traverse(username, dirname[:-1])
		if perm: 
			parent_name = dirname[-2]
			parent_acl = grandparent.get_acl()[parent_name]
			if parent_acl.is_writable(username):
				acl = ACL(dirname, signature_acl, dir_acl)
				de = DirEntry(dirname, username, {}, [])
				parent.add_dir(dirname, de, acl)
				mkdirmsg = "Created directory with dirname %s" % str(dirname)
				print mkdirmsg
				resp = OKResponse(mkdirmsg)
				return resp.getPayload(data)
		else:
			print msg
			resp = ErrorResponse(msg)
			return resp.getPayload(data)	

	def delete_file(self, username, filename):
		if username not in self.users:
			errmsg =  "User %s not registered" % username
			return ErrorResponse(errmsg)
		(perm, msg, parent) = self.traverse(username, filename)
		data = {}
		if perm:	
			parent.delete_file(filename)
			deletemsg = "File deleted with filename %s" % str(filename)
			print deletemsg
			resp = OKResponse(deletemsg)
			return resp.getPayload(data)
		else:
			print msg
			resp = ErrorResponse(msg)
			return resp.getPayload(data)

	def delete_dir(self, username, dirname):
		if username not in self.users:
			errmsg =  "User %s not registered" % username
			return ErrorResponse(errmsg)
		data = {}
		if (len(dirname) == 1):
			for home_e in self.files:
				if home_e.name = username:
					parent = home_e
					current_entry = parent.get_entry(dirname)
					if current_entry.is_deletable(username):
						parent.delete_dir(dirname)
						deletemsg = "Removed directory with dirname %s" % str(dirname)
						print deletemsg
						resp = OKResponse(deletemsg)
						return resp.getPayload({})
					else:
						errmsg = "Cannot delete directory. Insufficient permissions"
						print errmsg
						resp = ErrorResponse(errmsg)
						return resp.getPayload({})

		(perm, msg, grandparent) = self.traverse(username, dirname[:-1])
		if perm: 
			parent_name = dirname[-2]
			parent_acl = grandparent.get_acl()[parent_name]
			if parent_acl.is_writable(username):
				current_entry = parent.get_entry(dirname)
				if current_entry.is_deletable(username):
						parent.delete_dir(dirname)
						deletemsg = "Removed directory with dirname %s" % str(dirname)
						print deletemsg
						resp = OKResponse(deletemsg)
						return resp.getPayload({})
					else:
						errmsg = "Cannot delete directory. Insufficient permissions"
						print errmsg
						resp = ErrorResponse(errmsg)
						return resp.getPayload({})
			else: 
				errmsg1 = "Cannot delete directory. Insufficient permissions"
				print errmsg1
				resp = ErrorResponse(errmsg1)
				return resp.getPayload({})
		else:
			print msg
			resp = ErrorResponse(msg)
			return resp.getPayload(data)	

	def list_contents(self, username, dirname):
		if username not in self.users:
			errmsg =  "User %s not registered" % username
			return ErrorResponse(errmsg)
		(perm, msg, parent) = self.traverse(username, dirname)
		data = {}
		if perm:
			de = parent.get_entry(dirname)
			if de.is_readable(username):
				data["contents"] = de.get_names()
				lsmsg = "Sending list of contents in directory with name %s" % str(dirname)
				print lsmsg
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
			
		print "filename:", fn

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
				current_acls = current_dir.get_acl()
				if current_name not in current_acls:
					errmsg = "File doesn't exist, %s" % current_name
					return (False, errmsg)
				current_acl = current_acl[current_name]
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



