class ServerResponse:
	"""Server response message to socket interface"""
	status = None
	message = None
	payload = None

	def __init__(self, status, msg):
		self.status = status
		self.message = msg
		self.payload = {"status":self.status, "message":self.message}

	def __str__(self):
		return " ".join([self.status, self.message, "\r\n"])

	def getPayload(self, data):
		self.payload["data"] = data
		return self.payload

class OKResponse(ServerResponse):
	def __init__(self, msg):
		self.status = "OK"
		self.message = msg
		self.payload = {"status":self.status, "message":self.message}


class ErrorResponse(ServerResponse):
	def __init__(self, msg):
		self.status = "NO"
		self.message = msg
		self.payload = {"status":self.status, "message":self.msg}

class UserEntry:
	username = None
	public_key = None # RSA public key

	def __init__(self, username, public):
		self.username = username
		self.public_key = public

	def __str__(self):
		return self.username

class Entry:
	def__init__(self, name, acl, owner):
	self.name = name
	self.acl = acl #acl dictionary for all files/subdirectories, if file acl is {fn: <acl>}, else {fn:<acl>, subdir:<acl>,..}
	self.owner = owner

	def __str__:
		return self.name

	def get_acl(self):
		return self.acl

	def get_owner(self):
		return self.owner

	def get_name(self):
		return self.name

class DirEntry(Entry):
	def __init__(self, name, acl, owner):
		self.name = name
		self.acl = acl #acl dictionaryfor all subdirectories {subdirname: <acl>, subdirname:<acl>}
		self.owner = owner
		
	def is_dir(self):
		return True

	def is_file(self):
		return False

	def subdir_is_readable(self, username, subdir_name):
		return self.acl[subdir_name].is_readable(username);

	def subdir_is_writeable(self, username, subdir_name):
		return self.acl[subdir_name].is_readable(username);

	# def is_descendable(self, username):
	# 	return self.acl.is_readable(username)


class FileEntry(Entry):
	def __init__(self, name, acl, owner):
		self.name = name
		self.acl = acl #just acl file
		self.owner = owner 

	def is_file(self):
		return True

	def is_dir(self):
		return False

	def is_readable(self, username, name):
		return self.acl[name].is_readable(username)
	
	def is_writable(self, username, name):
		return self.acl[name].is_writable(username)


class ACL():
	def __init__(self, acl):
		self.acl = acl #{un1:{perm, sk}, un2:{perm, sk}}

	def get_users(self):
		return acl.keys()

	def get_users_readable(self):



