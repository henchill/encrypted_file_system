#!/usr/bin/env python2.7

from encrypt import *
from Crypto.PublicKey import RSA
import sys

fn = "encrypt.py"

with open(fn, "r") as f:
	reference = f.read()

try:
	# Test key generation
	test = 0
	k = RSA.generate(2048)
	print "TEST %d: PASS" % test

	# Test creating ciphertexts
	test = 1
	ciphertexts = encrypt_file(k, fn)
	print "TEST %d: PASS" % test

	# Test file decryption
	test = 2
	plaintext = decrypt_file(k, ciphertexts)
	if plaintext == reference:
		print "TEST %d: PASS" % test
	else:
		print "TEST %d: FAIL" % test

	# Test idempotence
	test = 3
	a = encrypt_filename(k, fn)
	b = encrypt_filename(k, fn)
	if a == b:
		print "TEST %d: PASS" % test
	else:
		print "TEST %d: FAIL" % test

	# Test decrypting file names
	test = 4
	c = decrypt_filename(k, a)
	d = decrypt_filename(k, b)
	if c == fn and d == fn:
		print "TEST %d: PASS" % test
	else:
		print "TEST %d: FAIL" % test

	# Test signing dictionary
	test = 5
	dictionary = {"foo": "bar", "garply": [1, "baz"]}
	sign_dictionary(k, dictionary)
	if "signature" in dictionary:
		print "TEST %d: PASS" % test
	else:
		print "TEST %d: FAIL" % test
	
	# Test signature verification
	test = 6
	if verify_dictionary(k, dictionary):
		print "TEST %d: PASS" % test
	else:
		print "TEST %d: FAIL" % test

	# Test bad dictionary verification
	test = 7
	dictionary["signature"] = "fail"
	if not verify_dictionary(k, dictionary):
		print "TEST %d: PASS" % test
	else:
		print "TEST %d: FAIL" % test

except Exception as e:
	print "TEST %d: EXCEPTION: %s" % (test, str(e))
	sys.exit(1)
