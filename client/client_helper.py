import base64

def createEncryptedMessage(user, server_pk, data):
    new_data = pickle.dumps(data)
    signature = user.key.sign(new_data, '')
    msg = Message(user.username, new_data, signature)
    encrypted_msg = server_pk.encrypt(pickle.dumps(msg), 
                                      Random.get_random_bytes(64))
    return base64.b64encode(pickle.dumps(encrypted_msg))