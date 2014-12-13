#!/usr/bin/env python2.7

import json
import time
import socket
import threading
import SocketServer
from encrypt import *
from Crypto.PublicKey import RSA
from server_helper import *

from encrypt import *
from Crypto.PublicKey import RSA

import traceback

# Server socket parameters

buffer_size = 1024
host = "localhost"
servername = "efs-server"
port = 1025

key_size = 2048
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
				print '\n\n\n'
				print json.dumps(data)
				print '\n\n\n'
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
				request_username = data["username"]
				if request_username in self.users:
					pub = self.users[request_username].public_key
					okmsg = "Sending public key of user %s" % username

				print okmsg
				resp = OKResponse(okmsg)
				return resp.getPayload({"public_key":{"N":pub.n, "e": pub.e}})

			elif handler == "filekey":
				user_pub = self.users[username].public_key
				if verify_inner_dictionary(user_pub, signature, data):
					print "Signature verfied. Providing shared key for directory..."
					resp = self.get_filekey(username, data["dirname"])
					return resp

			elif handler == "read_acl":
				user_pub = self.users[username].public_key
				if verify_inner_dictionary(user_pub, signature, data):
					print "Signature verfied. Providing read_acl request..."
					resp = self.read_acl(username, data["pathname"])
					return resp

			elif handler == "write_acl":
				user_pub = self.users[username].public_key
				if verify_inner_dictionary(user_pub, signature, data):
					print "Signature verfied. Trying to acquire acl for write_acl request..."
					resp = self.write_acl(username, data["pathname"],  data["acl"], data["signature_acl"])
					return resp


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
				if username not in self.users:
					print "No such user %s" % username
					return ErrorResponse("No such user %s" % username)
				user_pub = self.users[username].public_key
				if verify_inner_dictionary(user_pub, signature, data):
					print "Signature verfied. Trying to fetch file for read request..."
					resp = self.read(username, data["filename"])
					return resp
		
			elif handler == "write":
				if username not in self.users:
					print "No such user %s" % username
					return ErrorResponse("No such user %s" % username)
				user_pub = self.users[username].public_key
				if verify_inner_dictionary(user_pub, signature, data):
					print "Signature verfied. Trying to fetch file for write request..."
					resp = self.write(username, data["filename"], data["file"])
					return resp

			elif handler == "rename":
				print "Not implemented.."

			# DIRECTORY FUNCTIONS
			elif handler == "mkdir":
				if username not in self.users:
					print "No such user %s" % username
					return ErrorResponse("No such user %s" % username)
				user_pub = self.users[username].public_key
				if verify_inner_dictionary(user_pub, signature, data):
					print "Signature verfied. Trying to create directory..."
					resp = self.mkdir(username, data["dirname"], data["acl"], data["signature_acl"])
					return resp

			elif handler == "remove":
				user_pub = self.users[username].public_key
				if verify_inner_dictionary(user_pub, signature, data):
					print "Signature verfied. Trying to create directory..."
					resp = self.delete_dir(username, data["dirname"])
					return resp

			elif handler == "ls":
				user_pub = self.users[username].public_key
				if verify_inner_dictionary(user_pub, signature, data):
					print "Signature verfied. Trying to list directory..."
					resp = self.list_contents(username, data["dirname"])
					return resp

		except KeyError as ke:
			print "Couldn't find expected action. Please use --help to see possible commands."
			print ke
			print traceback.format_exc()

	
	def register(self, username, pub_key, table, acl_signature):
		if username in self.users:
			errmsg = "User %s already exists" % username
			return ErrorResponse(errmsg).getPayload({})

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

	def get_filekey(self, username, dirname):
		if username not in self.users:
			errmsg =  "User %s not registered" % username
			return ErrorResponse(errmsg)
		
		data = {}

		print "username = ", username, "dirname =", dirname

		if ((len(dirname) == 1 or len(dirname)==2) and self.is_username(dirname[0])): #case when dirname is just username, old or ((dirname[0] == username) and (len(dirname) == 2)
			data["filekey"] = self.home_acls[dirname[0]].get_filekey(username)
			filekeymsg = "Sending filekey for user %s and dirname %s" % (username, str(dirname))

			print filekeymsg
			resp = OKResponse(filekeymsg)
			# print "home acls: ", self.home_acls[username]
			print "return: ", data
			return resp.getPayload(data)

		else:
			(perm, msg, parent) = self.traverse(username, dirname)
			if perm: 
				de = parent.get_entry(dirname[-1])
				print "dirname: ", dirname
				print "parent: ", parent.name
				print "de: ", de
				data["filekey"] = de.get_filekey(username)
				filekeymsg = "Sending filekey for user %s and dirname %s" % (username, str(dirname))
				print filekeymsg
				resp = OKResponse(filekeymsg)
				return resp.getPayload(data)
			else:
				print msg
				resp = ErrorResponse(msg)
				return resp.getPayload(data)

	def is_username(self, name):
		if name in self.users:
			return True
		else:
			return False

	def read_acl(self, username, pathname):
		if username not in self.users:
			errmsg =  "User %s not registered" % username
			return ErrorResponse(errmsg)

		data = {}

		if ((len(pathname) == 1) and (pathname[0]==username)) or (len(pathname)==2 and pathname[0]==username): #reading acl for some home, check that username in acl
			send_acl = self.home_acls[username].get_acl_table()
			if username in send_acl:
				data["acl"] = send_acl
				readaclmsg = "Sending acl table for pathname %s" % str(pathname)
				print readaclmsg
				resp = OKResponse(readaclmsg)
				return resp.getPayload(data)
			else: 
				readacl_errmsg = "Found acl, but username not in ACL for %s. Permission Denied" % str(pathname)
				print readacl_errmsg
				resp = ErrorResponse(readacl_errmsg)
				return resp.getPayload(data)
		else:
			(perm, msg, parent) = self.traverse(username, pathname)
			if perm: 
				entry = parent.get_entry(pathname)
				
				if isinstance(pathname[-1], DirEntry):  #check parent for acl
					send_acl = parent.get_acl()[pathname[-1]].get_acl_table()
				else: 
					send_acl = entry.get_acl().get_acl_table()

				if username in send_acl:
					data["acl"] = send_acl
					readaclmsg = "Sending acl table for pathname %s" % str(pathname)
					print readaclmsg
					resp = OKResponse(readaclmsg)
					return resp.getPayload(data)
				else: 
					readacl_errmsg = "Found acl, but username not in ACL for %s. Permission Denied" % str(pathname)
					print readacl_errmsg
					resp = ErrorResponse(readacl_errmsg)
					return resp.getPayload(data)
			else:
				print msg
				resp = ErrorResponse(msg)
				return resp.getPayload(data)

	def write_acl(self, username, pathname, acl, signature_acl):
		if username not in self.users:
			errmsg =  "User %s not registered" % username
			return ErrorResponse(errmsg)

		data = {}

		new_acl = ACL(pathname, acl, signature_acl)
		if ((len(pathname) == 1) and (pathname[0]==username)) or (len(pathname)==2 and pathname[0]==username): #writing acl for home, check that username is owner
			if (pathname[0] == username): #only allow updating own home acl
				self.home_acls[username] = new_acl
				writeaclmsg = "Received acl table for pathname %s. Making update to acl" % str(pathname)
				print writeaclmsg
				resp = OKResponse(writeaclmsg)
				return resp.getPayload(data)
			else:
				writeacl_errmsg = "Trying to change another user's home acl. Permission Denied. "
				print writeacl_errmsg
				resp = ErrorResponse(writeacl_errmsg)
				return resp.getPayload(data)
		else:
			(perm, msg, parent) = self.traverse(username, pathname)
			if perm: 
				entry = parent.get_entry(pathname)
				if entry.is_owner(username):
					if isinstance(pathname[-1], DirEntry):  #check parent for acl
						parent.set_acl(pathname[-1], new_acl)
					else: 
						entry.set_acl(new_acl)
					writeaclmsg = "Received acl table for pathname %s. Making update to acl" % str(pathname)
					print writeaclmsg
					resp = OKResponse(writeaclmsg)
					return resp.getPayload(data)
				else:
					writeacl_errmsg = "Only onwer can change acl. Permission Denied. "
					print writeacl_errmsg
					resp = ErrorResponse(writeacl_errmsg)
					return resp.getPayload(data)	
			else:
				print msg
				resp = ErrorResponse(msg)
				return resp.getPayload(data)

	def create(self, username, filename, file_content, file_acl, signature_acl):
		if username not in self.users:
			errmsg =  "User %s not registered" % username
			return ErrorResponse(errmsg)
		(perm, msg, parent) = self.traverse(username, filename)
		data = {}
		if perm:	
			#Made it here => can create file in parent
			acl = ACL(filename, file_acl, signature_acl)
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
		if (len(dirname) == 1 or (len(dirname)==2 and dirname[0] == username)): #creating in home directory
			for home_e in self.files:
				if home_e.name == username:
					parent = home_e
					acl = ACL(dirname[-1], dir_acl, signature_acl)
					de = DirEntry(dirname[-1], username, {}, [])
					parent.add_dir(dirname[-1], de, acl)
					mkdirmsg = "Created directory with dirname %s" % str(dirname)
					print mkdirmsg
					resp = OKResponse(mkdirmsg)
					return resp.getPayload(data)

		(perm, msg, grandparent) = self.traverse(username, dirname[:-1])
		if perm: 
			parent_name = dirname[-2]
			parent_acl = grandparent.get_acl()[parent_name]
			if parent_acl.is_writable(username):
				acl = ACL(dirname, dir_acl, signature_acl)
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
				if home_e.name == username:
					parent = home_e
					current_entry = parent.get_entry(dirname[-1])
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
				current_entry = parent.get_entry(dirname[-1])
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
			de = parent.get_entry(dirname[-1])
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
		current = None

		if (self.is_username(filename[0])):
			current_dir = [p for p in self.files if p.name==filename[0]][0]
			# current_dir = current_dir[0]
			#current_dir = self.files[filename[0]]
		else:
			for p in self.files:
				if p.name == username:
					current_dir = p #set current_dir to home so that (aakriti, subdir) parses correctly as it goes through loop once
					break

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
					return (False, errmsg, "")
				else:
					for e in self.files:
						if e.name == filename[0]:
							current_dir = e
					continue
			else:
				current_acls = current_dir.get_acl() #will only reach here after it has traversed the above if once
				print "dir", current_dir, "acls", current_acls
				if current_name not in current_acls:
					errmsg = "Path doesn't exist, %s" % current_name
					return (False, errmsg, "")
				current_acl = current_acls[current_name]
				if (current_acl.is_readable(username) == False):
					errmsg =  "Permission denied %s" % current_name
					return (False, errmsg, "")
				else:
					current_dir = current_dir.get_entry(current_name)
					continue
		okmsg = "User has sufficient permissions.."
		return (True, okmsg, current_dir)

class EFSHandler(SocketServer.BaseRequestHandler):
	def receive(self):
		packets = None

		while packets is None or None in packets:
			try:
				# Get length of packet
				packet_length = 0
				data = ""
				while True:
					# Byte-wise receive data
					data = self.request.recv(1)
					if data is None or data == "":
						continue
					elif data == "{": # If we see the opening curly brace, we're done
						break
					else:
						length_digit = int(data)
						packet_length = (packet_length * 10) + length_digit
						print packet_length

				# Receive packet with known length
				data = "{"
				remaining_length = packet_length - len(data)
				while remaining_length > 0:
					partial_data = self.request.recv(remaining_length)
					if partial_data is None or partial_data == "":
						continue
					data += partial_data
					remaining_length = packet_length - len(data)

				# Load dictionary from JSON format
				d = json.loads(data)
				if packets is None:
					packets = [None] * d["count"]

				if packets[d["seq"]] is None:
					packets[d["seq"]] = d["payload"]
			except ValueError as ve:
				print "invalid packet (%s...), dropping" % data[:10]
				continue
			except KeyError as ke:
				print "valid packet but missing key"
				continue

		return packets

	def handle(self):
		data = self.receive()
		
		#plaintext = decrypt(efs_server.key, data)
		# if use_threaded:
		#	cur_thread = threading.current_thread()
		#	response = "{} responds, {}".format(cur_thread.name, data)
		# else:
		#	response = "Server responds: {}".format(data)

		tmp = json.loads("".join(data))
		response = json.dumps(efs_server.handle_request(tmp))
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



