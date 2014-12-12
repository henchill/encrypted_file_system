import client
import sys
sys.path.insert(0, '/home/henchill/Documents/Workspace/encrypted_file_system/server')

from server import *
from encrypt import *

if __name__ == "__main__":
 
    resp = client.register('bottom')
    resp = client.register('henchill')
    # print "register: ", resp
    
    

    client.signIn('henchill')
    resp = client.createFile("test.txt")
    # print "create file: ", resp

    resp = client.createDirectory("foo");
    print "create dir: ", resp

    resp = client.writeFile('test.txt');
    print "write file: ", resp

    resp = client.readFile('test.txt');
    print "read file: ", resp

    resp = client.setPerm('test.txt', 'r', ['bottom'])
    print "write acl: ", resp

    resp = client.listDir('foo')
    # print "list dir: ", resp

"""
def createDirectory(name):
    enc_dirs, key = _getEncryptedFilePath(name)
    new_key, cipher = _getAESCipher()
    
    acl = {CURRENT_USER: {'perm': ['1', '1'],
                      'shared_key': encrypt(USER_PK, new_key)}}
    signature_acl = sign_inner_dictionary(USER_PRK, acl)
    
    data = {'username': CURRENT_USER,
            'action': 'mkdir',
            'dirname': enc_dirs,
            'acl': acl,
            'signature_acl': signature_acl}
    
    signature = sign_inner_dictionary(USER_PRK, data)
    
    msg = json.dumps({'username': CURRENT_USER,
                      'signature': signature,
                      'data': data})
    
    response = _transmitToServer(msg)
    respdata = json.loads(response) #json.loads(decrypt(rsa_key.exportKey('PEM'), response))
    
    status = {
        'status': respdata['status'],
        'message': respdata['message']
    }
    return status
"""