import json
import socket

from encrypt import *

class EFSConnection:
	"""Class representing a connection to the server.

	Use as follows:

	with EFSConnection(host, port) as c:
		c.transmit(key, plaintext)
	"""

	host = None
	port = None

	connection = None

	def __init__(self, host, port):
		self.host = host
		self.port = port

	def __enter__(self):
		self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.connection.connect((self.host, self.port))
		return self

	def __exit__(self, type, value, traceback):
		self.connection.close()

	def transmit_ciphertexts(self, ciphertexts):
		"""Send an array of ciphertexts through a socket."""

		packet_count = len(ciphertexts)
		packet_seq = 0

		for ciphertext in ciphertexts:
			packet = {"seq": packet_seq, "count": packet_count, "payload": ciphertext}
			packet_json = json.dumps(packet)

			# Prepend packet length to packet (not including length string itself)
			length = len(packet_json)
			packet_string = str(length) + packet_json

			self.connection.send(packet_string)
			# print packet_string
			packet_seq += 1

	def transmit(self, key, text):
		"""Send a string encrypted on key through a socket."""

		ciphertexts = encrypt(key, text)
		self.transmit_ciphertexts(ciphertexts)

