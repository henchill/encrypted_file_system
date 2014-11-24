#!/usr/bin/env python2.7

import sys
import json
import base64
import socket
from thread import *

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto import Random

server = None

# Crypto parameters
RSA_KEY_SIZE = 2048

# Server socket parameters
SERVER_PORT = 1026
MAX_PACKET_SIZE = 1024
MAX_CONNECTIONS = 10

class ServerResponse:
	"""Server response message to client requests."""
	status = None
	payload = None

	def __init__(self, status, payload):
		self.status = status
		self.payload = payload

	def __str__(self):
		return " ".join([self.status, self.payload, "\r\n"])


class OKResponse(ServerResponse):
	def __init__(self, msg):
		self.status = "OK"
		self.payload = msg

class ErrorResponse(ServerResponse):
	def __init__(self, msg):
		self.status = "NO"
		self.payload = msg


class ServerThread:
	"""Represents a single connection to the server."""
	conn = None

	def __init__(self, conn):
		self.conn = conn
		self.receive_requests()

	def handle_request(self, req):
		# Perform actions based on dict received
		try:
			action = req["action"]

			# REGISTER
			if action == "register":
				name = req["name"]
				dh = req["dh"]

				# rebuild user public key
				pub = req["pub"]
				N = long(pub["N"])
				e = long(pub["e"])
				rsa_pub = RSA.construct((N, e))

				resp = server.register(name, dh, rsa_pub)
				self.conn.sendall(str(resp))

			# KEY
			elif action == "key":
				pub = server.key.publickey()
				okmsg = "(%lu, %lu)" % (pub.n, pub.e)
				resp = OKResponse(okmsg)
				self.conn.sendall(str(resp))

			# CREATE
			elif action == "create":
				pass

			else:
				print "Invalid message:", data
				self.conn.sendall("Invalid message.")

		except KeyError as ke:
			print "Couldn't find expected data value"

	def receive_requests(self):
		try:
			while True:
				data = self.conn.recv(MAX_PACKET_SIZE)
				if not data:
					break

				# Try decoding from JSON
				try:
					req = json.loads(data)
				except ValueError as ve:
					print "Invalid message received"
					continue

				self.handle_request(req)
		except Exception as e:
			print "Exception:", e
			pass
		finally:
			self.conn.close()

class Server:
	name = None

	host = ''
	port = SERVER_PORT

	key = None # RSA public/private key pair

	users = None
	files = None

	def __init__(self, name):
		self.name = name
		self.key = RSA.generate(RSA_KEY_SIZE)
		self.users = {}
		self.files = {}
	
	def create_worker(self, conn):
		print "creating worker..."
		worker = ServerThread(conn)

	# binary tides
	def listen(self):
		print "Server", self.name, "is listening"

		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		print "Socket created"

		try:
			s.bind((self.host, self.port))
		except socket.error as msg:
			print "Bind failed, error", msg[1]
			sys.exit()

		s.listen(MAX_CONNECTIONS)
		print "Socket now listening..."
			
		try:
			while True:
				conn, addr = s.accept()
				print "Connected with", addr[0], ":", str(addr[1])

				start_new_thread(self.create_worker, (conn,))

			s.close()
		except (KeyboardInterrupt, Exception) as k:
			s.close()
			sys.exit(0)
		finally:
			s.close()

	def register(self, name, dh, pk):
		if name in self.users:
			errmsg = "User %s already exists" % name
			return ErrorResponse(errmsg)

		u = UserEntry(name, dh, pk)
		self.users[name] = u
		okmsg = "Added user %s" % str(u)

		resp = OKResponse(okmsg)
		return resp

	def create(self, user, filename, blob):
		if user not in self.users:
			errmsg = "User %s doesn't exist" % user
			print errmsg
			return ErrorResponse(errmsg)

		self.files[filename] = blob
		print "created filename", filename, "->", base64.b64encode(blob)
		

class UserEntry:
	name = None
	dh_key = None # Diffie-Hellman key
	public_key = None # RSA public key

	def __init__(self, name, dh, public):
		self.name = name
		self.dh_key = dh
		self.public_key = public

	def __str__(self):
		return self.name


if __name__ == "__main__":
	server = Server("foo bar")
	server.listen()

