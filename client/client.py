import socket as sock_conn
import json
import base64
import os

from client_objects import *
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import AES

from efs_helper.encrypt import *
from efs_helper.transceive import *

HOME_DIRECTORY = os.path.join(os.environ['HOME'], 'efs_local')
SERVER_PK = None
USER_PK = None
USER_PRK = None
EFS_Connection = None
CURRENT_USER = ""
CURRENT_DIRECTORY = None
CURRENT_DIRECTORY_SK = None
CURRENT_PATH = ""

BLOCK_SIZE = 32
HOST = 'localhost'
PORT = 1027

def register(socket, username):
    key_msg = {'username': username, 'data': { 'action': 'key', 'username': 'server'}}
    resp = json.loads(_transmitToServer(None, key_msg))
    if (resp['status'] == 'success'):
        SERVER_PK = RSA.importKey(resp['public_key'])
    else:
        status = {'status': 'error',
                  'message': 'failed to obtain server pk'}
        return status
    
    rsa_key = RSA.generate(2048)
    public_key = rsa_key.publickey().exportKey('PEM')
    key, cipher = _getAESCipher()
    CURRENT_DIRECTORY = [cipher.encrypt(username)]
    CURRENT_DIRECTORY_SK = [key]
    CURRENT_PATH = os.path.join(CURRENT_PATH, username)
    
    acl = {username: {'perm': '11', 'shared_key': encrypt(public_key, key)}}
    data = {
        'username': username,
        'action': 'register',
        'public_key': public_key,
        'user_dir': username,
        'acl': acl
    }

    signature = sign_dictionary(rsa_key.exportKey('PEM'), data)

    msg = base64.b64encode(json.dumps({
        'username': username,
        'signature': signature,
        'data': data
        }))
    
    response = _transmitToServer(SERVER_PK, msg)
    respdata = json.loads(decrypt(rsa_key.exportKey('PEM'), response))

    status = {
        'status': respdata['status'],
        'message': respdata['message']
    }

    if (respdata['status'] == 'success'): 
        _initLocalStorage(username, rsa_key)
        
    return status

def signIn(username):
    # init socket EFS_Connection
    CURRENT_USER = username
    _getServerPublicKey()
    USER_PK = _getUserPublicKey(username)
    USER_PRK = _getUserPrivateKey(username)
    
def createFile(name, data=None):
    """
    C: { username, signature, data:{username, action:create, filename, file, acl}}
    S: { status, message, data:{ {} } }
    """
    
    enc_dirs, key = _getEncryptedFilePath(name)
    acl = {username: '11'}
    signature_acl = sign_dictionary(USER_PRK, acl)
    
    key, cipher = _getAESCipher(key)
    contents = cipher.encrypt(readFileContents(name))    
    
    data = {'username': CURRENT_USER, 
            'action': 'create', 
            'filename': enc_dirs,
            'file': contents,
            'acl': acl,
            'signature_acl': signature_acl
            }
    signature = sign_dictionary(USER_PRK, data)
    
    msg = base64.b64encode(json.dumps({'username': CURRENT_USER,
           'signature': signature,
           'data': data}))
    
    response = _transmitToServer(SERVER_PK, msg)
    respdata = json.loads(decrypt(rsa_key.exportKey('PEM'), response))
    
    status = {
        'status': respdata['status'],
        'message': respdata['message']
    }
    return status

def createDirectory(name):
    enc_dirs, key = _getEncryptedFilePath(name)
    key, cipher = _getAESCipher(key)
    enc_dirs = enc_dirs[:-1]
    enc_dirs.append(cipher.encrypt(name))
    
    key, cipher = _getAESCipher()
    
    acl = {username: {'perm': '11', 'shared_key': encrypt(USER_PK, key)}}
    signature_acl = sign_dictionary(USER_PK, acl)
    
    
    
    data = {'username': CURRENT_USER,
            'action': mkdir,
            'dirname': enc_dirs,
            'acl': acl,
            'signature_acl': signature_acl}
    
    signature = sign_dictionary(USER_PRK, data)
    
    msg = base64.b64encode(json.dumps({'username': CURRENT_USER,
                                       'signature': signature,
                                       'data': data}))
    
    response = _transmitToServer(SERVER_PK, msg)
    respdata = json.loads(decrypt(rsa_key.exportKey('PEM'), response))
    
    status = {
        'status': respdata['status'],
        'message': respdata['message']
    }
    return status

def delete(name):
    raise NotImplementedError

def writeFile(name, data=None):
    enc_dirs, key = _getEncryptedFilePath(name)
    key, cipher = _getAESCipher(key)
    
    acl = {username: '11'}
    signature_acl = sign_dictionary(USER_PRK, acl)
    
    contents = readFileContents(name)
    if (contents == ""): 
        status = {'status': 'error',
                  'message': 'cannot write empty file to server'}
        return status
    
    contents = cipher.encrypt(contents) 
    
    data = {'username': CURRENT_USER, 
            'action': 'write', 
            'filename': enc_dirs,
            'file': contents}
    signature = sign_dictionary(USER_PRK, data)
    
    msg = base64.b64encode(json.dumps({'username': CURRENT_USER,
           'signature': signature,
           'data': data}))
    
    response = _transmitToServer(SERVER_PK, msg)
    respdata = json.loads(decrypt(rsa_key.exportKey('PEM'), response))
    
    status = {
        'status': respdata['status'],
        'message': respdata['message']
    }
    return status

def rename(oldname, newname):
    raise NotImplementedError

def readFile(name):
    enc_dirs, key = _getEncryptedFilePath(name)
    
    data = {'username': CURRENT_USER, 
            'action': 'read', 
            'filename': enc_dirs}
    
    signature = sign_dictionary(USER_PRK, data)
    
    msg = base64.b64encode(json.dumps({'username': CURRENT_USER,
           'signature': signature,
           'data': data}))
    
    response = _transmitToServer(SERVER_PK, msg)
    respdata = json.loads(decrypt(rsa_key.exportKey('PEM'), response))
    status = {
        'status': respdata['status'],
        'message': respdata['message']
    }
    
    if (status['status'] != 'error'):
        contents = respdata['data']['file']
        filename = respdata['data']['filename']
        
        key, cipher = _getAESCipher(key)
        contents = cipher.decrypt(contents)
        filename = cipher.decrypt(filename)
        if (filename != name):
            status['status'] = 'error'
            status['message'] = "couldn't obtain correct file"
            return status
        _writeFileToLocal(filename, contents)
        return status
    return status

def listDir(name):
    enc_dirs, key = _getEncryptedFilePath(name)
    data = {'username': CURRENT_USER,
            'action': 'ls',
            'dirname': enc_dirs}
    
    signature = sign_dictionary(USER_PRK, data)
    
    msg = base64.b64encode(json.dumps({'username': CURRENT_USER,
           'signature': signature,
           'data': data}))
    
    response = _transmitToServer(SERVER_PK, msg)
    respdata = json.loads(decrypt(rsa_key.exportKey('PEM'), response))

    ls_contents = []
    key, cipher = _getAESCipher(key)
    for f in respdata['contents']:
        ls_contents.append(cipher.decrypt(f))
        
    resp = {
        'status': respdata['status'],
        'message': respdata['message'],
        'dir-list': ls_contents
    }
    return resp

def setPerm(obj, perm, users):
    enc_dirs, key = _getEncryptedFilePath(obj)
    
    data = {'username': CURRENT_USER,
            'action': 'read-acl',
            'name': enc_dirs}
    
    signature = sign_dictionary(USER_PRK, data)
    
    msg = base64.b64encode(json.dumps({'username': CURRENT_USER,
           'signature': signature,
           'data': data}))
    
    response = _transmitToServer(SERVER_PK, msg)
    respdata = json.loads(decrypt(rsa_key.exportKey('PEM'), response))
    
    acl = respdata['data']['acl']
    if (type(acl[CURRENT_USER]) == type({})):
        for u in users:
            key_msg = {'username': CURRENT_USER, 'data': { 'action': 'key', 'username': u}}
            resp = json.loads(_transmitToServer(None, key_msg))
            public_key = resp['data']['public_key']
            acl[u] = {'perm': perm, 'shared_key': encrypt(public_key, key)}
    else: 
        for u in users:
            acl[u] = {'perm': perm}

def changeDirectory(name):
    dir_list, basename = _buildDirectoryNames(name)
    dir_list.append(basename)
    if dir_list[0] == '':
        for dr in dir_list[1:]:
            _changeToDir(dr)
    else:
        CURRENT_DIRECTORY = []
        for dr in dir_list[1:]:
            _changeToDir(dr)
    resp = {'status': 'success',
            'curr_dir': CURRENT_PATH}

def _changeToDir(dr):
    if (dr == '..' and len(CURRENT_DIRECTORY) > 0):
        del CURRENT_DIRECTORY[-1]
        del CURRENT_DIRECTORY_SK[-1]
        CURRENT_PATH = os.path.dirname(CURRENT_PATH)
    else:
        current_sk = CURRENT_DIRECTORY_SK[-1]
        key, cipher = _getAESCipher(currenk_sk)
        CURRENT_PATH = os.path.join(CURRENT_PATH, dr)
        dr = cipher.encrypt(dr)
        CURRENT_DIRECTORY.append(cipher.encrypt(dr))
        CURRENT_DIRECTORY_SK.append(_getSharedKey(dr))
        
        
def readFileContents(name):
    filename = os.path.join(HOME_DIRECTORY, name)
    file_contents = ""
    if (os.path.isfile(filename)):
        f = open(filename, 'r')
        contents = f.read()
        f.close()
    return contents

def readAclContents(name):
    filename = "." + os.path.join(HOME_DIRECTORY, name) + ".acl"
    contents = ""
    if (os.path.isfile(filename)):
        f = open(filename, 'r')
        contents = f.read()
        f.close()
    return contents

def _writeFileToLocal(filename, contents):
    f = open(filename, 'rw')
    f.write(contents)
    f.close
    
def _getEncryptedFilePath(name):
    dir_list, basename = _buildDirectoryNames(name)
    shared_keys = []
    enc_dirs = []
    current_sk = None
    if (dir_list[0] == '/'):
        current_enc_dir = dir_list[1]
        current_sk = _getSharedKey(current_enc_dir)
        dir_list = dir_list[2:]
        enc_dirs.append(current_enc_dir)
    else:
        current_sk = CURRENT_DIRECTORY_SK[-1]
        dir_list = dir_list[1:]
        tmp = list(CURRENT_DIRECTORY).extend(enc_dirs)
        encr_dirs = tmp        
    
    for dirname in dir_list:
        key, cipher = _getAESCipher(currenk_sk)
        enc_dir = _encryptAES(cipher, dirname)
        enc_dirs.append(enc_dir)
        current_sk = _getSharedKey(enc_dir)
        
    key, cipher = _getAESCipher(currenk_sk)
    enc_dir = _encryptAES(cipher, dirname)
    enc_dirs.append(enc_dir)
    return (enc_dirs, current_sk)

def _getSharedKey(dirname):
    data = {'action': 'shared_key',
            'dirname': dirname,
            'username': CURRENT_USER}
    resp = json.loads(_transmitToServer(SERVER_PK, data))
    return decrypt(_getUserPrivateKey(), resp['shared_key'])
    
def _buildDirectoryNames(name):
    dirs = []
    parent = os.path.dirname(name)
    while parent != "" or parent != "/":
        dirs.insert(0, parent)
        parent = os.path.dirname(parent)
    dirs.insert(0, parent)
    return (dirs, os.path.basename(name))

def _transmitToServer(key, text):
    with EFSConnection(HOST, PORT) as c:
        c.transmit(key, plaintext)
        return c.recv(1024)

def _initLocalStorage(username, key):
    if not os.path.exists(HOME_DIRECTORY):
        os.makedirs(HOME_DIRECTORY)
    filename = os.path.join(HOME_DIRECTORY, user['username'] + "_%s_key.pem")
    f = open(filename % 'public', 'w')
    f.write(key.publickey().exportKey('PEM'))
    f.close()
    
    f = open(filename % 'private', 'w')
    f.write(key.exportKey('PEM'))
    f.close()
    
    server_pub = os.path.join(HOME_DIRECTORY, 'server_pk.pem')
    f = open(server_pub, 'w')
    f.write(server_pub.exportKey('PEM'))
    f.close()
    
def _getServerPublicKey():
    server_pub = os.path.join(HOME_DIRECTORY, 'server_pk.pem')
    f = open(server_pub, 'r')
    SERVER_PK = RSA.importKey(f.read())
    f.close()

def _getUserPublicKey(username):
    filename = os.path.join(HOME_DIRECTORY, username + '_public_key.pem')
    f = open(filename, 'r')
    key = RSA.importKey(f.read())
    f.close()
    return key

def _getUserPrivateKey(username):
    filename = os.path.join(HOME_DIRECTORY, username + '_private_key.pem')
    f = open(filename, 'r')
    key = RSA.importKey(f.read())
    f.close()
    return key

def _padString(s):
    return s + ((BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE))

def _unPad(s):
    return s[:-ord(s[len(s)-1:])]

def _getAESCipher(key=None):
    if (key == None): 
        key = os.urandom(32)
    cipher = AES.new(key)
    return (key, cipher)

def _encryptAES(cipher, plaintext):
    return base64.b64encode(cipher.encrypt(_padString(plaintext)))

def _decryptAES(cipher, ciphertext):
    return _unPad(cipher.decrypt(base64.b64decode(ciphertext)).decode('utf-8'))
    