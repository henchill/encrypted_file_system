import json
import base64

from Crypto.Signature import PKCS1_PSS
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA
from Crypto import Random

def chunk_size(key):
	"""Returns the maximum PKCS1_OAEP encryption length.

	This is the size of the RSA modulus (N) in bytes, minus two
	times the digest (SHA-1) size, minus 2.
	"""

	return (key.size() / 8) - (2 * SHA.digest_size) - 2 - 10

def encrypt(key, plaintext, pad=True):
	"""Encypts filenames (an arbitrary string) of any length."""

	ciphertexts = []

	print "trying to encrypt:", plaintext

	if pad:
		cipher = PKCS1_OAEP.new(key)
		for start in xrange(0, len(plaintext), chunk_size(key)):
			end = start + chunk_size(key)
			chunk = plaintext[start:end]
			print "chunk =", chunk.decode("utf-8")
			ciphertext = cipher.encrypt(chunk)
			ciphertexts.append(base64.b64encode(ciphertext))
	else:
		for start in xrange(0, len(plaintext), chunk_size(key)):
			end = start + chunk_size(key)
			chunk = plaintext[start:end]
			# K=0 is required but ignored parameter
			ciphertext = key.encrypt(chunk, K=0)[0]
			ciphertexts.append(base64.b64encode(ciphertext))

	return ciphertexts

def decrypt(key, ciphertexts, pad=True):
	"""Decrypts file contents from an arbitrary number of chunks."""

	plaintext = ""
	if pad:
		cipher = PKCS1_OAEP.new(key)
		for ciphertext in ciphertexts:
			plaintext += cipher.decrypt(base64.b64decode(ciphertext))
	else:
		for ciphertext in ciphertexts:
			plaintext += key.decrypt(base64.b64decode(ciphertext))

	return plaintext

def encrypt_file(key, filename):
	"""Encrypts the contents of the named file into an array of ciphertexts."""

	ciphertexts = []
	with open(filename, "r") as f:
		ciphertexts = encrypt(key, f.read())

	return ciphertexts

def decrypt_file(key, ciphertexts):
	return decrypt(key, ciphertexts, pad=True)

def encrypt_filename(key, filename):
	"""Encrypts the filename into an array of ciphertexts.

	This does not pad the filename, so two encryptions of the same text
	will yield the same encrypted string.
	"""

	return encrypt(key, filename, pad=False)

def decrypt_filename(key, ciphertext):
	return decrypt(key, ciphertext, pad=False)

def sign_dictionary(key, d):
	"""Signs the contents of the dictionary as encoded in JSON.

	This modifies the dictionary to have a "signature" key. It must
	not already be present in the dictionary.
	"""

	if "signature" in d:
		raise KeyError("signature object already present")

	dict_str = json.dumps(d)
	h = SHA.new()
	h.update(dict_str)
	signer = PKCS1_PSS.new(key)

	signature = signer.sign(h)
	d["signature"] = base64.b64encode(signature)

def verify_dictionary(key, d):
	"""Verifies the contents of the dictionary based on its signature."""

	original = d.copy()
	# Remove the signature key
	del original["signature"]
	dict_str = json.dumps(original)
	h = SHA.new()
	h.update(dict_str)

	signature = base64.b64decode(d["signature"])

	verifier = PKCS1_PSS.new(key)
	return verifier.verify(h, signature)

def encrypt_aes(key, plaintext):
	"""Symmetrically encrypts the plaintext with the key.

	Returns a (ciphertext, iv) tuple.

	In addition to the base64-encoded ciphertext, the algorithm returns
	an initialization vector (IV). This can be public, but should be
	randomly generated. It is provided for the decryption function.
	"""

	iv = Random.new().read(AES.block_size)
	cipher = AES.new(key, AES.MODE_CFB, iv)
	ciphertext = cipher.encrypt(plaintext)

	b64_iv = base64.b64encode(iv)
	b64_ciphertext = base64.b64encode(ciphertext)

	return (b64_ciphertext, b64_iv)

def decrypt_aes(key, b64_iv, b64_ciphertext):
	"""Symmetrically decrypts the plaintext with the key and initialization vector (IV)."""

	iv = base64.b64decode(b64_iv)
	ciphertext = base64.b64decode(b64_ciphertext)
	cipher = AES.new(key, AES.MODE_CFB, iv)

	return cipher.decrypt(ciphertext)

def verify_inner_dictionary(key, signature, d):
	"""Verifies the contents of the dictionary based on its signature."""

	dict_str = json.dumps(d, sort_keys=True)
	h = SHA.new()
	h.update(dict_str)

	signature = base64.b64decode(signature)

	verifier = PKCS1_PSS.new(key)
	return verifier.verify(h, signature)

def sign_inner_dictionary(key, d):
	"""Signs the contents of the dictionary as encoded in JSON.
	"""

	dict_str = json.dumps(d, sort_keys=True)
	h = SHA.new()
	h.update(dict_str)
	signer = PKCS1_PSS.new(key)

	signature = signer.sign(h)

	return base64.b64encode(signature)
