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
		self.payload = {"status":self.status, "message":msg}

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
		self.filekeys = {}
		self.contents = contents #[subdir DE and file FE]	

	def is_home(self, username):
		return self.name == username

	def get_acl(self):
		return self.acl

	def get_entry(self, name):
		for e in self.contents:
			if e.name == name:
				return e

	def get_filekey(self, username):
		return self.filekeys[username]

	def add_dir(self, subdir_name, subdir_entry, subdir_acl):
		self.acl[subdir_name] = subdir_acl
		self.contents.append(subdir_entry)
		if subdir_entry.owner not in self.filekeys:
			self.filekeys[subdir_entry.owner] = subdir_acl.get_filekey(subdir_entry.owner)

	def add_file(self, file_entry):
		self.contents.append(file_entry)
		if file_entry.owner not in self.filekeys:
			self.filekeys[file_entry.owner] = file_entry.get_acl().get_filekey(file_entry.owner)

	def delete_file(self, filename):
		e = self.get_entry(filename)
		self.contents.remove(e)

	def get_names(self):
		names = []
		for e in self.contents:
			names.append(e.name)
		return names

	def is_deletable(self, username):
		for e in self.contents:
			if e.name in self.acl: #is subdir
				if (self.acl[e.name].is_writable(username) == False):
					return False
			else: #is file
				if (e.get_acl().is_writable(username) == False):
					return False
		return True

	def delete_dir(self, subdir_name):
		de = self.get_entry(subdir_name)
		del self.acl[subdir_name]
		self.contents.remove(de)

class FileEntry(Entry):
	def __init__(self, name, owner, acl, file_contents):
		self.name = name
		self.acl = acl #just acl file
		self.owner = owner 
		self.contents = file_contents

	def is_readable(self, username):
		return self.acl.is_readable(username)
	
	def is_writable(self, username):
		return self.acl.is_writable(username)

	def get_acl(self):
		return self.acl

	def get_contents(self):
		return self.contents

	def set_contents(self, new_contents):
		self.contents = new_contents

class ACL:
	filename = None
	table = None #{username: {'perm':[R, W], 'shared_key': 'xxxx'}}
	signature = None

	PERM = 'perm'
	SKEY = 'shared_key'
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
			return self.table[user][self.PERM][self.ACL_READ] == "1"

	def is_writable(self, user):
		if user in self.table:
			return self.table[user][self.PERM][self.ACL_WRITE] == "1"

	def get_filekey(self, user):
		if user in self.table:
			return self.table[user][self.SKEY]
