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