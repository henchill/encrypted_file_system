class Message(): 
    def __init__(self, user, data, signature): 
    	self.user = user
    	self.data = data
    	self.signature = signature

class Session():
    def __init__(self, username, rsa_key, dh_secret, dh_prime, dh_base, server_pk):
    	self.current_user = username
    	self.rsa_key = rsa_key
    	self.dh_key = (dh_secret, dh_prime, dh_base)
    	self.shared_keys = {} # key: filename value: shared key

    def add_shared_key(self, fname, key):
    	self.shared_keys[fname] = key
   
   def save(self):
        # save user and write info to file
        # consider using json
        raise NotImplementedError

   def loadUser():
        # load user data from file
        raise NotImplementedError