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
	def __init__(self, name, acl, owner, contents):
		self.name = name
		self.acl = acl #acl dictionary for all files/subdirectories, if file acl is {fn: <acl>}, else {fn:<acl>, subdir:<acl>,..}
		self.owner = owner
		self.contents = contents

	def __str__(self):
		return self.name

	def get_acl(self):
		return self.acl

	def get_owner(self):
		return self.owner

	def get_name(self):
		return self.name




class DirEntry(Entry):
	def __init__(self, name, owner, acl, contents):
		self.name = name
		self.acl = acl #acl dictionaryfor all subdirectories {subdirname: <acl>, subdirname:<acl>}
		self.owner = owner
		self.contents = contents #[subdir DE and file FE]

	def is_home(self, username):
		return self.name == username

	def add_file(self, file_entry):
		self.contents.append(file_entry)

	def get_acl(self):
		return self.acl

	def get_entry(self, name):
		for e in self.contents:
			if e.name == name:
				return e

	def subdir_is_readable(self, username, subdir_name):
		return self.child_acls[subdir_name].is_readable(username);

	def subdir_is_writeable(self, username, subdir_name):
		return self.child_acls[subdir_name].is_readable(username);

	# def is_descendable(self, username):
	# 	return self.acl.is_readable(username)



class FileEntry(Entry):
	def __init__(self, name, owner, acl, file_contents):
		self.name = name
		self.acl = acl #just acl file
		self.owner = owner 
		self.contents = file_contents

	def is_readable(self, username, name):
		return self.acl.is_readable(username)
	
	def is_writable(self, username, name):
		return self.acl.is_writable(username)

	def get_acl(self):
		return self.acl

	def get_file(self):
		return self.contents
		



class ACL:
	filename = None
	table = None
	signature = None

	ACL_READ = 0
	ACL_WRITE = 1

	def __init__(self, filename, signature, table):
		self.filename = filename
		self.table = table
		self.signature = signature

	def is_valid(self, key):
		if self.signature is None:
			return False

		representation = {"filename": self.filename, "table": self.table}
		return verify_inner_dictionary(key, self.signature, representation)

	def is_readable(self, user):
		if user in self.table:
			return self.table[user][ACL_READ] == "1"

	def is_writable(self, user):
		if user in self.table:
			return self.table[user][ACL_WRITE] == "1"
