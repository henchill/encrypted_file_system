#!/usr/bin/env python2.7

import json
import time
import socket
import threading
import SocketServer

from encrypt import *
from Crypto.PublicKey import RSA

buffer_size = 1024
host = "localhost"
servername = "efs-server"
port = 1025

key_size = 2048
use_threaded = False

efs_server = None

class EFSServer:
	key = None

	def __init__(self):
		try:
			keyfile = open("server.key", "r")
			self.key = RSA.importKey(keyfile.read())
		except IOError as e:
			print "No server.key file, making one."
			keyfile = open("server.key", "w")
			self.key = RSA.generate(key_size)
			keyfile.write(self.key.exportKey("PEM"))
			keyfile.close()

		print "Public key (N,e) is (%lu,%lu)" % (self.key.n, self.key.e)

	def handle_request(self, request):
		print "I am supposed to handle:", str(request)

	# Your code here

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
		plaintext = decrypt(efs_server.key, data)
		# if use_threaded:
		#	cur_thread = threading.current_thread()
		#	response = "{} responds, {}".format(cur_thread.name, data)
		# else:
		#	response = "Server responds: {}".format(data)
		efs_server.handle_request(plaintext)
		# self.request.sendall(response)

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
