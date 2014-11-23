class Message(): 
	def __init__(self, user, action, dst_obj, data, signature): 
		self.user = user
		self.action = action
		self.dst_obj = dst_obj
		self.data = data
		self.signature = signature
