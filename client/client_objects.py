class Message(): 
    def __init__(self, user, data, signature): 
        self.user = user
        self.data = data
        self.signature = signature

class User():
    def __init__(self, username, rsa_key):
        self.username = username
        self.rsa_key = rsa_key
        self.shared_keys = {} # key: filename value: shared key

    def get_public_key(self):
        return self.rsa_key.publicKey()

    def get_private_key(self):
        pass

    def get_shared_key(self, path):
        pass

    def save_user(self):
        pass

    def sign(self, data):
        pass
            
    def load_user_from_file(filename):
        # returns user session information


