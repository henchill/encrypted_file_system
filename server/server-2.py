#!/usr/bin/env python2.7

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

debug = True

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

			if action == "register":
				return self.register(data, signature)
			elif action == "key":
				return self.get_key(data)

		except KeyError as ke:
			print "Couldn't find key:", ke
			print traceback.format_exc()

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
		if username in [user.name for user in self.users]:
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
		elif requested_username in [user.name for user in self.users]:
			key = user.public_key
			msg = "Public key of user %s is" % requested_username
		else:
			return ErrorResponse("No user named %s" % requested_username)

		data = {"public_key": {"N": key.n, "e": key.e}}

		return DictResponse(msg, data)


class Entry:
	def __init__(self, name, owner, acl):
		self.name = name
		self.owner = owner
		self.acl = acl


class DirectoryEntry(Entry):
	def __init__(self, name, owner, acl):
		Entry.__init__(self, name, owner, acl)
		self.subdirectories = []
		self.files = []


class FileEntry(Entry):
	def __init__(self, name, owner, acl, contents):
		Entry.__init__(self, name, owner, acl)
		self.contents = contents


class ACL:
	def __init__(self, owner, filename, table, signature):
		self.owner = owner
		self.filename = filename
		self.table = table
		self.signature = signature
		

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
			self.request.sendall(str(response))

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
