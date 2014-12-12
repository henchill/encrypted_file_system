#!/usr/bin/env python2.7

import sys
import json
import base64
import socket
from thread import *

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto import Random

server = None

# Crypto parameters
RSA_KEY_SIZE = 2048

# Server socket parameters
SERVER_PORT = 1027
MAX_PACKET_SIZE = 1024
MAX_CONNECTIONS = 10

# Data transmission parameters
CHUNK_SIZE = 200

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


class FileResponse(ServerResponse):
	filename = None
	seq = None
	length = None
	chunk = None

	def __init__(self, filename, seq, length, chunk):
		self.status = "OK"
		self.payload = ""
		self.filename = filename
		self.seq = seq
		self.length = length
		self.chunk = chunk

	def __str__(self):
		response = {"response": self.status, "filename": self.filename, "seq": self.seq, "length": self.length, "chunk": self.chunk}
		response_str = json.dumps(response)
		return response_str


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

			# DECRYPT
			elif action == "decrypt":
				ciphertexts = req["ciphertexts"]
				plaintext = ""
				cipher = PKCS1_OAEP.new(server.key)

				try:
					for ciphertext in ciphertexts:
						plaintext += cipher.decrypt(base64.b64decode(ciphertext))
				except ValueError as ve:
					print "Decryption failed"
					return

				print "Decrypted message: %s" % plaintext

			# CREATE
			elif action == "create":
				user = req["user"]
				filename = req["filename"]
				blob = ""
				resp = server.create(user, filename, blob)
				self.conn.sendall(str(resp))

			# READ
			elif action == "read":
				filename = req["filename"]
				seq = req["seq"]

				resp = server.read(filename, seq)
				self.conn.sendall(str(resp))

			# WRITE
			elif action == "write":
				filename = req["filename"]
				length = req["length"]
				seq = req["seq"]
				blob = req["blob"]

				resp = server.write(filename, length, seq, blob)
				self.conn.sendall(str(resp))

			else:
				print "Invalid message:", data
				self.conn.sendall("Invalid message.")

		except KeyError as ke:
			print "Couldn't find expected data value"

	def receive_requests(self):
		try:
			while True:
				data = self.conn.recv(MAX_PACKET_SIZE)
				if data is None or data == "":
					break
				print "received", data

				# Try decoding from JSON
				try:
					req = json.loads(data)
				except ValueError as ve:
					print "Message is not JSON"
					break

				self.handle_request(req)
		except Exception as e:
			print "Exception:", e
			pass
		finally:
			self.conn.close()


class Server:
	host = ''
	port = SERVER_PORT

	key = None # RSA public/private key pair

	users = None
	files = None

	def __init__(self):
		self.key = RSA.generate(RSA_KEY_SIZE)
		self.users = {}
		self.files = {}
	
	def create_worker(self, conn):
		print "creating worker..."
		worker = ServerThread(conn)

	# binary tides
	def listen(self):
		print "Server is listening"

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
		print okmsg

		resp = OKResponse(okmsg)
		return resp

	def create(self, user, filename, blob):
		if user not in self.users:
			errmsg = "User %s doesn't exist" % user
			print errmsg
			return ErrorResponse(errmsg)

		f = FileEntry(filename)
		f.owner = user
		self.files[filename] = FileEntry(filename)
		
		okmsg = "Created file %s for user %s" % (filename, user)
		print okmsg
		return OKResponse(okmsg)

	def write(self, filename, length, seq, blob):
		if filename not in self.files:
			errmsg = "File %s doesn't exist" % filename
			print errmsg
			return ErrorResponse(errmsg)

		f = self.files[filename]
		chunks = length / CHUNK_SIZE + 1

		if f.intact():
			f.length = length
			f.blob = [None] * chunks
		else:
			if f.length != length:
				errmsg = "Length thought to be %d but file not completely written" % (chunks)
				print errmsg
				return ErrorResponse(errmsg)

		if seq >= chunks or seq < 0:
			errmsg = "Chunk sequence number %d out of range (0 <= seq < %d)" % (seq, chunks)
			print errmsg
			return ErrorResponse(errmsg)

		f.blob[seq] = blob
		okmsg = "File %s... (%d/%d)" % (filename[0:10], seq + 1, chunks)
		print okmsg
		return OKResponse(okmsg)

	def read(self, filename, seq):
		if filename not in self.files:
			errmsg = "File %s doesn't exist" % filename
			print errmsg
			return ErrorResponse(errmsg)

		f = self.files[filename]
		chunks = f.length / CHUNK_SIZE + 1

		if not f.intact():
			errmsg = "File is not intact"
			print errmsg
			return ErrorResponse(errmsg)

		if seq >= chunks or seq < 0:
			errmsg = "Chunk sequence number %d out of range (0 <= seq < %d)" % (seq, chunks)
			print errmsg
			return ErrorResponse(errmsg)

		chunk = f.blob[seq]

		resp = FileResponse(filename, seq, f.length, chunk)
		return resp


class FileEntry:
	filename = None
	owner = None
	length = None
	blob = None

	def __init__(self, filename, length=0):
		self.filename = filename
		self.length = length
		self.blob = []

	def __str__(self):
		return "File " + self.filename

	# Is the blob (an array, typically) complete? Did we send all
	# necessary packets? Phrased another way, is it ready to be
	# overwritten?
	def intact(self):
		if self.blob is None:
			return True
		for b in self.blob:
			if b is None:
				return False
		return True


class UserEntry:
	name = None
	public_key = None # RSA public key

	def __init__(self, name, dh, public):
		self.name = name
		self.dh_key = dh
		self.public_key = public

	def __str__(self):
		return self.name


if __name__ == "__main__":
	server = Server()
	server.listen()

