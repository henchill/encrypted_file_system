import json
from encrypt import *

def encode(dictionary):
	return json.dumps(dictionary)

def decode(json_text):
	return json.loads(json_text)

def transmit_ciphertexts(connection, ciphertexts):
	"""Send an array of ciphertexts through a socket."""

	packet_count = len(ciphertexts)
	packet_seq = 0

	for ciphertext in ciphertexts:
		packet = {"seq": packet_seq, "count": packet_count, "payload": ciphertext}
		packet_json = encode(packet)
		# connection.sendall(packet_json)
		print packet_json
		packet_seq += 1

def transmit(connection, key, text):
	"""Send a string encrypted on key through a socket."""

	ciphertexts = encrypt(key, text)
	transmit_ciphertexts(connection, ciphertexts)
