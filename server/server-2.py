#!/usr/bin/env python2.7

import stat
import time
import socket
import threading
import traceback
import SocketServer

from encrypt import *
from transmit import *

buffer_size = 1024
host = "localhost"
servername = "efs-server"
port = 1025

use_threaded = False

efs_server = None

debug = False

class EFSServer:
	def __init__(self):
		self.users = [] # User
		self.homedirs = {} # username -> DirectoryEntry
		self.homeacls = {} # username -> ACL

		self.key = RSA.generate(2048)

	def handle_request(self, request):
		if debug:
			print "Request:", str(request)

		try:
			action = request["data"]["action"]

			data = request["data"]
			username = request["username"]
			signature = request["signature"]

			# Getting a key has no signature check
			if action == "key":
				return self.get_key(data)

			# Registering has its own signature check
			if action == "register":
				return self.register(data, signature)

			# Signatures required for all others
			if not self.verify_user_request(username, signature, data):
				if debug:
					print "[handle_request] Signature verification failed."
				return ErrorResponse("[handle_request] Signature verification failed.")

			if action == "filekey":
				return self.get_filekey(username, data)
			elif action == "read_acl":
				return self.get_acl(username, data)
			elif action == "mkdir":
				return self.mkdir(username, data)
			elif action == "write_acl":
				return self.write_acl(username, data)
			elif action == "create":
				return self.create(username, data)
			elif action == "read":
				return self.read(username, data)
			elif action == "write":
				return self.write(username, data)
			elif action == "remove":
				return self.remove(username, data)
			elif action == "ls":
				return self.listing(username, data)
			elif action == "getattr":
				return self.getattr(username, data)
			elif action == "exists":
				return self.exists(username, data)

		except KeyError as ke:
			print "Couldn't find key:", ke
			print traceback.format_exc()

	def verify_user_request(self, username, signature, data):
		# User exists?
		if not self.is_user(username):
			return False

		# Get user's key
		for user in self.users:
			if user.name == username:
				user_public_key = user.public_key

		return verify_inner_dictionary(user_public_key, signature, data)

	def register(self, data, signature):
		public_key_dict = data["public_key"]
		N = long(public_key_dict["N"])
		e = long(public_key_dict["e"])

		user_public_key = RSA.construct((N, e))

		# Verify data signature with public key
		if not verify_inner_dictionary(user_public_key, signature, data):
			return ErrorResponse("[register] Signature verification failed.")

		# Check if username exists
		username = data["username"]
		if self.is_user(username):
			return ErrorResponse("[register] User %s already exists." % username)

		user = User(username, user_public_key)
		self.users.append(user)
		print "[register] Added user %s" % username

		# Create home directory
		homedir = DirectoryEntry(username, username, None)
		self.homedirs[username] = homedir
		print "[register] Created homedir"

		# Create home directory ACL
		acl_table = data["acl"]
		acl_signature = data["signature_acl"]
		homeacl = ACL(username, username, acl_table, acl_signature)
		self.homeacls[username] = homeacl
		print "[register] Created homedir ACL"

		return DictResponse("Added user %s" % username, {})

	def get_key(self, data):
		requested_username = data["username"]

		if requested_username == "" or requested_username == "server":
			key = self.key
			msg = "Public key of server is"
		elif self.is_user(requested_username):
			for user in self.users:
				if requested_username == user.name:
					key = user.public_key
			msg = "Public key of user %s is" % requested_username
		else:
			return ErrorResponse("No user named %s" % requested_username)

		data = {"public_key": {"N": key.n, "e": key.e}}

		return DictResponse(msg, data)

	def get_filekey(self, requester, data):
		if not self.is_user(requester):
			return ErrorResponse("User %s is not registered" % requester)

		path = self.resolve_path(requester, data["dirname"])

		node = self.traverse(path)
		if not node:
			return ErrorResponse("File doesn't exist")

		if self.is_homedir(path):              # home directories have own ACLs
			filekey = self.homeacls[path[0]].get_filekey(requester)
		elif isinstance(node, DirectoryEntry): # directories stored in parent
			parent = self.traverse_to_parent(path)
			filename = path[-1]
			parent_acl = parent.acl[filename]
			filekey = parent_acl.get_filekey(requester)
		elif isinstance(node, FileEntry):      # file ACL stored in file itself
			filekey = node.acl.get_filekey(requester)

		print "[filekey] Filekey sent for", [(name[:10] + "...") for name in path]

		return DictResponse("Filekey is", {"filekey": filekey})

	def get_acl(self, requester, data):
		if not self.is_user(requester):
			return ErrorResponse("User %s is not registered" % requester)

		path = self.resolve_path(requester, data["pathname"])

		node = self.traverse(path)
		if not node:
			return ErrorResponse("File doesn't exist")

		if self.is_homedir(path):
			acl = self.homeacls[path[0]]
		elif isinstance(node, DirectoryEntry):
			parent = self.traverse_to_parent(path)
			filename = path[-1]
			acl = parent.acl[filename]
		elif isinstance(node, FileEntry):
			acl = node.acl

		print "[get_acl] ACL sent for", [(name[:10] + "...") for name in path]

		data = {"acl": acl.table}

		return DictResponse("ACL is", {"acl": acl.table})

	def mkdir(self, username, data):
		if not self.is_user(username):
			return ErrorResponse("User %s is not registered" % username)

		full_path = self.resolve_path(username, data["dirname"])
		print "[mkdir] full_path =", full_path
		name = full_path[-1]

		# Create ACL
		acl_table = data["acl"]
		acl_signature = data["signature_acl"]
		acl = ACL(username, username, acl_table, acl_signature)
		print "[mkdir] Created ACL for directory %s..." % name[:10]

		# Traverse and get parent
		parent = self.traverse_to_parent(full_path)
		directory = DirectoryEntry(name, username, acl)
		parent.acl[name] = acl
		print "[mkdir] Created directory with name %s..." % name[:10]

		parent.contents.append(directory)

		return DictResponse("Created directory", {})

	def write_acl(self, username, data):
		if not self.is_user(username):
			return ErrorResponse("User %s is not registered" % username)

		path = self.resolve_path(username, data["pathname"])

		# Create ACL
		acl_table = data["acl"]
		acl_signature = data["signature_acl"]
		acl = ACL(username, username, acl_table, acl_signature)

		# Traverse and write ACL
		node = self.traverse(path)
		if not node:
			return ErrorResponse("File doesn't exist")

		if self.is_homedir(path):
			self.homeacls[path[0]] = acl
		elif isinstance(node, DirectoryEntry):
			parent = self.traverse_to_parent(path)
			filename = path[-1]
			parent.acl[filename] = acl
		elif isinstance(node, FileEntry):
			node.acl = acl

		print "[set_acl] ACL set for", [(name[:10] + "...") for name in path]

		return DictResponse("ACL set", {})

	def create(self, username, data):
		if not self.is_user(username):
			return ErrorResponse("User %s is not registered" % username)

		full_path = self.resolve_path(username, data["filename"])
		print "[create] full_path =", [(name[:10] + "...") for name in full_path]
		name = full_path[-1]

		# Create ACL
		acl_table = data["acl"]
		acl_signature = data["signature_acl"]
		acl = ACL(username, username, acl_table, acl_signature)

		# Traverse and write ACL
		contents = data["file"]
		length = data["length"]
		parent = self.traverse_to_parent(full_path)
		new_file = FileEntry(name, username, acl, contents, length)
		parent.contents.append(new_file)
		print "[create] Created file %s..." % name[:10]

		return DictResponse("Created file", {})

	def read(self, username, data):
		if not self.is_user(username):
			return ErrorResponse("User %s is not registered" % username)

		full_path = self.resolve_path(username, data["filename"])
		print "[read] full_path =", [(name[:10] + "...") for name in full_path]
		name = full_path[-1]

		node = self.traverse(full_path)
		if not node:
			return ErrorResponse("File doesn't exist")
		elif not isinstance(node, FileEntry):
			return ErrorResponse("Path specifies something that's not a file")

		data = {"filename": full_path, "file": node.contents}

		print "[read] Read file %s..." % name[:10]

		return DictResponse("Read file", data)

	def write(self, username, data):
		if not self.is_user(username):
			return ErrorResponse("User %s is not registered" % username)

		full_path = self.resolve_path(username, data["filename"])
		print "[write] full_path =", [(name[:10] + "...") for name in full_path]
		name = full_path[-1]

		node = self.traverse(full_path)
		if not node:
			return ErrorResponse("File doesn't exist")
		elif not isinstance(node, FileEntry):
			return ErrorResponse("Path specifies something that's not a file")

		node.contents = data["file"]
		node.length = data["length"]

		print "[write] Wrote file %s..." % name[:10]

		return DictResponse("Wrote file", {})

	def remove(self, username, data):
		if not self.is_user(username):
			return ErrorResponse("User %s is not registered" % username)

		full_path = self.resolve_path(username, data["filename"])
		print "[remove] full_path =", [(name[:10] + "...") for name in full_path]
		name = full_path[-1]

		if self.is_homedir(full_path):
			return ErrorResponse("Can't remove a home directory")

		parent = self.traverse_to_parent(full_path)
		node = self.traverse(full_path)

		if not node:
			return ErrorResponse("File doesn't exist")
		elif isinstance(node, DirectoryEntry) and node.contents:
			return ErrorResponse("Can't remove non-empty directory")

		parent.contents.remove(node)

		print "[remove] Deleted file %s..." % name[:10]

		return DictResponse("Removed file", {})

	def listing(self, username, data):
		if not self.is_user(username):
			return ErrorResponse("User %s is not registered" % username)

		full_path = self.resolve_path(username, data["dirname"])
		print "[listing] full_path =", [(name[:10] + "...") for name in full_path]

		# Listing root is listing users
		if self.is_root(full_path):
			root_data = {"contents": [user.name for user in self.users]}
			return DictResponse("Listing is", root_data)

		node = self.traverse(full_path)
		if not isinstance(node, DirectoryEntry):
			return ErrorResponse("Can't list a non-directory")

		data = {"contents": [entry.name for entry in node.contents]}

		return DictResponse("Listing is", data)

	def getattr(self, username, data):
		if not self.is_user(username):
			return ErrorResponse("User %s is not registered" % username)

		full_path = self.resolve_path(username, data["filename"])
		print "[getattr] full_path =", [(name[:10] + "...") for name in full_path]
		name = full_path[-1]

		attr = {"st_atime": 0,
				"st_ctime": 0,
				"st_gid":   0,
				"st_mode":  0,
				"st_mtime": 0,
				"st_nlink": 0,
				"st_size":  0,
				"st_uid":   0}

		# Special case root directory
		if full_path == ["/"]:
			attr["st_mode"] = stat.S_IFDIR | stat.S_IRWXO
			return DictResponse("Root attributes are:", attr)

		node = self.traverse(full_path)
		if not node:
			return ErrorResponse("File doesn't exist")

		file_permissions = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH

		if isinstance(node, DirectoryEntry):
			attr["st_mode"] = stat.S_IFDIR | stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO
		elif isinstance(node, FileEntry):
			attr["st_mode"] = stat.S_IFREG | file_permissions
			attr["st_size"] = node.length

		return DictResponse("Attributes are", attr)

	def exists(self, username, data):
		if not self.is_user(username):
			return ErrorResponse("User %s is not registered" % username)

		full_path = self.resolve_path(username, data["filename"])

		node = self.traverse(full_path)

		data = {"exists": (node is not None)}

		return DictResponse("Exists?", data)

	# Helper functions
	def is_user(self, name):
		return name in [user.name for user in self.users]

	def is_homedir(self, path):
		return len(path) == 1 and path[0] in self.homedirs

	def is_root(self, path):
		return len(path) == 1 and path[0] == "/"

	# Path name methods
	def resolve_path(self, username, path):
		if self.is_root(path): # If root, do nothing
			return path

		homedir = path[0]
		if homedir in self.homedirs: # If resolved, do nothing
			return path
		elif username not in [user.name for user in self.users]:
			raise ValueError("username doesn't exist, so can't resolve path")
		else:
			return [username] + path

	def traverse_to_parent(self, path):
		homedir = path[0]
		if not homedir in self.homedirs:
			raise ValueError("Path must be fully resolved (user's name is not first)")

		if len(path) == 1:
			raise ValueError("Cannot obtain parent of a home directory")
			# return homedir

		return self.traverse(path[:-1])

	def traverse(self, path):
		"""Returns the FileEntry or DirectoryEntry corresponding to the fully resolved path."""
		homedir_path = path[0]
		if not homedir_path in self.homedirs:
			raise ValueError("Path must be fully resolved (user's name is not first)")

		homedir = self.homedirs[homedir_path]

		# If it's just the homedir, return that
		if len(path) == 1:
			return homedir

		# Traverse the structure
		current_directory = homedir
		i = 1
		while i < len(path) - 1:
			node_name = path[i]
			for entry in current_directory.contents:
				if entry.name == node_name:
					current_directory = entry

			if not isinstance(current_directory, DirectoryEntry):
				raise ValueError("Intermediate directory isn't actually a directory")

			i += 1

		leaf_name = path[i]
		for entry in current_directory.contents:
			if entry.name == leaf_name:
				return entry

		print "[traverse] Path not found:", [(name[:10] + "...") for name in path]

# OBJECT CLASS DEFINITIONS


class Entry:
	def __init__(self, name, owner, acl):
		self.name = name
		self.owner = owner
		self.acl = acl


class DirectoryEntry(Entry):
	def __init__(self, name, owner, acl):
		Entry.__init__(self, name, owner, {})
		self.contents = []


class FileEntry(Entry):
	def __init__(self, name, owner, acl, contents, length):
		Entry.__init__(self, name, owner, acl)
		self.contents = contents
		self.length = length


class ACL:
	PERM = 'perm'
	ACL_READ = 0
	ACL_WRITE = 1

	def __init__(self, owner, filename, table, signature):
		self.owner = owner
		self.filename = filename
		self.table = table
		self.signature = signature

	def get_filekey(self, user):
		if user in self.table:
			return self.table[user]["shared_key"]
		return None

class Response:
	def __init__(self, status, payload):
		self.status = status
		self.payload = payload

	def __str__(self):
		return " ".join([self.status, self.payload, "\r\n"])


class OKResponse(Response):
	def __init__(self, msg):
		Response.__init__(self, "OK", msg)


class ErrorResponse(Response):
	def __init__(self, msg):
		Response.__init__(self, "ERROR", msg)


class DictResponse(Response):
	def __init__(self, msg, data):
		Response.__init__(self, "DICT", "")
		self.data = {}
		self.data["data"] = data
		self.data["status"] = "OK"
		self.data["message"] = msg


class User:
	def __init__(self, name, public_key):
		self.name = name
		self.public_key = public_key


# SERVER

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

		temp = json.loads("".join(data))

		response = efs_server.handle_request(temp)

		if isinstance(response, DictResponse):
			response_text = json.dumps(response.data)
			if debug:
				print "Server response:", response_text
			self.request.sendall(response_text)
		else:
			response_dict = {"status": response.status, "message": response.payload}
			self.request.sendall(json.dumps(response_dict))

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
	except Exception as e:
		print "Exception,", e
	finally:
		server.shutdown()
