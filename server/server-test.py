
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
	data["public_key"] = {"N":alice["key"].publickey().n, "e":alice["key"].publickey().e}

	
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
	data["filename"] = ["alice", "foo.txt"]
	data["file"] = "content is bar"
	data["acl"] = {alice["username"]: "11"}

	req["username"] = alice["username"]
	req["data"] = data
	req["signature"] = sign_inner_dictionary(alice["key"], data)
	resp = server.handle_request(req)
	if "message" in resp:
		print "TEST %s: PASS" % test
	else:
		print "TEST %s: FAIL" % test
