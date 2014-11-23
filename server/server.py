#!/usr/bin/env python2.7

import socket
from thread import *
import sys
import base64

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto import Random

server = None

class Message:
	status = ""
	payload = ""

	def __init__(self, status, payload):
		self.status = status
		self.payload = payload

	def __str__(self):
		return status + " " + payload

class ServerThread:
	conn = None

	def __init__(self, conn):
		self.conn = conn
		self.client_thread()

	def client_thread(self):
		while True:
			data = self.conn.recv(1024)
			if not data:
				break

			if data.startswith("register"):
				self.conn.sendall("Got register\r\n")
				reg = data.strip().split(" ")
				name = reg[1]
				dh = reg[2]
				pub = reg[3]
				resp = server.register(name, dh, pub)
				conn.sendall(str(resp))

			elif data.startswith("create"):
				self.conn.sendall("Got create file\r\n")
				create = data.strip().split(" ")
				user = create[1]
				blob = create[2]
				server.create(user, blob)

			else:
				self.conn.sendall("don't know what to do with " + data)

		self.conn.close()

class Server:
	name = ""
	host = ""
	port = 1027
	key = None

	users = {}
	files = {}

	def __init__(self, name):
		self.name = name
		self.key = RSA.generate(2048)
	
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

		s.listen(10)
		print "Socket now listening..."
			
		while True:
			conn, addr = s.accept()
			print "Connected with", addr[0], ":", str(addr[1])

			start_new_thread(self.create_worker, (conn,))

		s.close()

	def register(self, name, dh, pk):
		u = UserEntry(name, dh, pk)
		self.users[name] = u
		print "Added user", str(u)
		pub = self.key.publickey()
		resp = Message("OK", "(%lu, %lu)" % (pub.n, pub.e))
		return resp

	def create(self, user, filename, blob):
		if user not in self.users:
			print "User %s doesn't exist" % user
		self.files[filename] = blob
		print "created filename", filename, "->", base64.b64encode(blob)
		

class UserEntry:
	name = ""
	dh_key = None # Diffie-Hellman key
	public_key = None

	def __init__(self, name, dh, public):
		self.name = name
		self.dh_key = dh
		self.public_key = public

	def __str__(self):
		return self.name


if __name__ == "__main__":
	server = Server("foo bar")
	server.listen()

