#!/usr/bin/env python2.7

from Crypto.PublicKey import RSA
from server import *
from encrypt import *

# Crypto parameters
RSA_KEY_SIZE = 2048

if __name__ == "__main__":
	server = EFSServer()
	alice = {"username":"Alice", "key": RSA.generate(RSA_KEY_SIZE)}
	bob = {"username":"Bob", "key": RSA.generate(RSA_KEY_SIZE)}
	eve = {"username":"Eve", "key": RSA.generate(RSA_KEY_SIZE)}
	jill = {"username":"Jill", "key": RSA.generate(RSA_KEY_SIZE)}
	

	#TEST REGISTER
	test="REGISTER"
	req = {}
	data = {}
	
	data["action"] = "register"
	data["username"] = alice["username"]
	data["public_key"] = {"N":alice["key"].n, "e":alice["key"].e}
	data["acl"] = {alice["username"]: "11"}
	data["signature_acl"] = sign_inner_dictionary(alice["key"], data["acl"])

	req["username"]= alice["username"]
	req["data"] = data
	req["signature"] = sign_inner_dictionary(alice["key"], data)
	resp = server.handle_request(req)
	if "message" in resp:
		print "TEST %s: PASS" % test
	else:
		print "TEST %s: FAIL" % test

	#TEST KEY
	test="KEY"
	req = {}
	data = {}
	
	data["action"] = "key"
	data["username"] = alice["username"]
	
	req["username"]= alice["username"]
	req["data"] = data
	req["signature"] = sign_inner_dictionary(alice["key"], data)
	resp = server.handle_request(req)
	if "message" in resp:
		print "TEST %s: PASS" % test
	else:
		print "TEST %s: FAIL" % test

	#TEST CREATE
	test="CREATE"
	req = {}
	data = {}

	data["action"] = "create"
	data["username"] = alice["username"]
	data["filename"] = ["foo.txt"]
	data["file"] = "content is bar"
	data["acl"] = {alice["username"]: "11"}
	data["signature_acl"] = sign_inner_dictionary(alice["key"], data["acl"])

	req["username"] = alice["username"]
	req["data"] = data
	req["signature"] = sign_inner_dictionary(alice["key"], data)
	resp = server.handle_request(req)
	if "message" in resp:
		print "TEST %s: PASS" % test
	else:
		print "TEST %s: FAIL" % test

	# TEST READ 1
	test = "READ 1"
	data = {"action": "read",
	        "username": alice["username"],
	        "filename": ["foo.txt"]}
	        
	req = {"username": alice["username"],
	       "data": data,
	       "signature": sign_inner_dictionary(alice["key"], data)}

	resp = server.handle_request(req)
	if "message" in resp:
		print "TEST %s: PASS" % test
		print "contents:", resp["data"]["file"]
	else:
		print "TEST %s: FAIL" % test
	
	# TEST WRITE
	test = "WRITE"
	data = {"action": "write",
	        "username": alice["username"],
	        "filename": ["foo.txt"],
	        "file": "content is garply"}
	        
	req = {"username": alice["username"],
	       "data": data,
	       "signature": sign_inner_dictionary(alice["key"], data)}

	resp = server.handle_request(req)
	if "message" in resp:
		print "TEST %s: PASS" % test
	else:
		print "TEST %s: FAIL" % test

	# TEST READ 2
	test = "READ 2"
	data = {"action": "read",
	        "username": alice["username"],
	        "filename": ["foo.txt"]}
	        
	req = {"username": alice["username"],
	       "data": data,
	       "signature": sign_inner_dictionary(alice["key"], data)}

	resp = server.handle_request(req)
	if "message" in resp:
		print "TEST %s: PASS" % test
		contents = resp["data"]["file"]
		print "contents:", contents
	else:
		print "TEST %s: FAIL" % test

	# TEST READ 3
	test = "READ 3"
	data = {"action": "read",
	        "username": bob["username"],
	        "filename": ["foo.txt"]}

	req = {"username": bob["username"],
	       "data": data,
	       "signature": sign_inner_dictionary(bob["key"], data)}

	resp = server.handle_request(req)
	print "TEST %s: PASS" % test
	
	# TEST MKDIR
	test = "MKDIR"
	acl = {alice["username"]: "11"}
	data = {"action": "mkdir",
	        "username": alice["username"],
	        "dirname": ["foobaz"],
	        "acl": acl,
	        "signature_acl": sign_inner_dictionary(alice["key"], acl)}

	req = {"username": alice["username"],
	       "data": data,
	       "signature": sign_inner_dictionary(alice["key"], data)}

	resp = server.handle_request(req)
	if "message" in resp:
		print "TEST %s: PASS" % test
	else:
		print "TEST %s: FAIL" % test
