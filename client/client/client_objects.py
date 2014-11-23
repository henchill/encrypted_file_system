class Message(): 
	def __init__(self, action, user, dst_obj, data, signature): 
		self.action = action
		self.user = user
		self.dst_obj = dst_obj
		self.data = data
		self.signature = signature

class User():
	def __init__(self, username):
		self.username = username
		self.shared_keys = {} # key: filename value: shared key

	def add_rsa_key(self, key):
		self.key = key

	def add_dh_key(self, secret, prime, base):
		self.dh_key = (secret, prime, base)

	def add_shared_key(self, fname, key):
		self.shared_keys[fname] = key