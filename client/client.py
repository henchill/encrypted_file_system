import socket as sock_conn
import json
import base64
import os
import sys
sys.path.insert(0, '../server')

from encrypt import *
from transmit import *

from client_objects import *
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import AES
from Crypto import Random

HOME_DIRECTORY = os.path.join(os.environ['HOME'], 'efs_local')
SERVER_PK = None
USER_PK = None
USER_PRK = None

CURRENT_USER = ""
CURRENT_DIRECTORY = None
CURRENT_DIRECTORY_SK = None
CURRENT_PATH = ""

BLOCK_SIZE = 32
HOST = 'localhost'
PORT = 1025

def register(username):
    global CURRENT_PATH, CURRENT_DIRECTORY, CURRENT_DIRECTORY_SK
    global SERVER_PK, USER_PK, USER_PRK, CURRENT_USER
    
    USER_PRK = RSA.generate(2048)
    USER_PK = USER_PRK.publickey()
    key, cipher = _getAESCipher()
    print "register shared key", key
    CURRENT_DIRECTORY = [username]
    CURRENT_DIRECTORY_SK = [key]
    CURRENT_PATH = os.path.join(CURRENT_PATH, username)
    print "current_path_register: ", CURRENT_PATH
    key_msg = {'username': username, 'data': { 'action': 'key', 
                                                'username': 'server'}}
    key_sig = sign_inner_dictionary(USER_PRK, key_msg['data'])
    key_msg['signature'] = key_sig
    resp = _transmitToServer(json.dumps(key_msg))
    resp = json.loads(resp)
    if resp['status'] == 'OK':
        SERVER_PK = RSA.construct((long(resp['data']['public_key']['N']),
                                   long(resp['data']['public_key']['e'])))
    else:
        status = {'status': 'error',
                  'message': 'failed to obtain server pk'}
        return status
    
    acl = {username: {'perm': ['1', '1'], 'shared_key': encrypt(USER_PK, key)}}
    data = {
        'username': username,
        'action': 'register',
        'public_key': {'N': USER_PK.n, 'e': USER_PK.e},
        'acl': acl,
        'signature_acl': sign_inner_dictionary(USER_PRK, acl)
    }

    signature = sign_inner_dictionary(USER_PRK, data)

    msg = json.dumps({
        'username': username,
        'signature': signature,
        'data': data })
    
    response = _transmitToServer(msg) #should be encrypted in the future
    print "response to register: ", response
    respdata = json.loads(response) #json.loads(decrypt(rsa_key, response))

    status = {
        'status': respdata['status'],
        'message': respdata['message']
    }

    if (respdata['status'] == 'OK'): 
        CURRENT_USER = username
        _initLocalStorage()
        
    return status

def signIn(username):
    global CURRENT_PATH, CURRENT_USER, CURRENT_DIRECTORY, CURRENT_DIRECTORY_SK
 
    # init socket EFS_Connection
    print "get info for username: %s" % username
    CURRENT_USER = username 
    _getServerPublicKey() #SERVER_PK
    _getUserPublicKey(username) #USER_PK
    _getUserPrivateKey(username) #USER_PRK

    shared_key = _getSharedKey([username])
    # print "shared key signin: ", shared_key
    if (CURRENT_DIRECTORY == None or CURRENT_DIRECTORY_SK == None):
        CURRENT_DIRECTORY = [username]
        CURRENT_DIRECTORY_SK = [shared_key]
    if (CURRENT_PATH == ""):
        CURRENT_PATH = os.path.join(CURRENT_PATH, username)
    else: 
        CURRENT_PATH = os.path.join("", username)
    
def createFile(name, data=None):
    """
    C: { username, signature, data:{username, action:create, filename, file, acl}}
    S: { status, message, data:{ {} } }
    """
    print "create file started"
    enc_dirs, key = _getEncryptedFilePath(name)
    # print "key: ", key
    # print "enc_dirs: ", enc_dirs
    print "key to encrypt: ", key, "\n userpk: ", USER_PK
    print encrypt
    acl = {CURRENT_USER: {'perm': ['1', '1'],
                          'shared_key': encrypt(USER_PK, key)}}
    signature_acl = sign_inner_dictionary(USER_PRK, acl)
    
    key, cipher = _getAESCipher(key)
    contents = _encryptAES(cipher, "" """readFileContents(name)""")    

    data = {'username': CURRENT_USER, 
            'action': 'create', 
            'filename': enc_dirs,
            'file': contents,
            'acl': acl,
            'signature_acl': signature_acl
            }
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

def createDirectory(name):
    enc_dirs, key = _getEncryptedFilePath(name)
    print "dir create: ", enc_dirs, ' key: ', key
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
    # TODO: create the file locally
    return status

def delete(name):
    raise NotImplementedError

def writeFile(name, local):
    enc_dirs, key = _getEncryptedFilePath(name)
    key, cipher = _getAESCipher(key)
    
    # acl = {CURRENT_USER: ['1', '1']}
    # signature_acl = sign_inner_dictionary(USER_PRK, acl)
    
    contents = readFileContents(local)
    if (contents == ""): 
        status = {'status': 'error',
                  'message': 'cannot write empty file to server'}
        return status
    
    contents = _encryptAES(cipher, contents) 
    
    data = {'username': CURRENT_USER, 
            'action': 'write', 
            'filename': enc_dirs,
            'file': contents}
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

def rename(oldname, newname):
    raise NotImplementedError

def readFile(name):
    enc_dirs, key = _getEncryptedFilePath(name)
    
    data = {'username': CURRENT_USER, 
            'action': 'read', 
            'filename': enc_dirs}
    
    signature = sign_inner_dictionary(USER_PRK, data)
    
    msg = json.dumps({'username': CURRENT_USER,
           'signature': signature,
           'data': data})
    
    response = _transmitToServer(msg)
    print "respossne: ", response   
    respdata = json.loads(response) #json.loads(decrypt(rsa_key.exportKey('PEM'), response))
    status = {
        'status': respdata['status'],
        'message': respdata['message']
    }
    
    if (status['status'] == 'OK'):
        contents = respdata['data']['file']
        filename = respdata['data']['filename'][-1]
        
        key, cipher = _getAESCipher(key)
        contents = _decryptAES(cipher, contents)
        filename = _decryptAES(cipher, filename)
        if (filename != name):
            status['status'] = 'error'
            status['message'] = "couldn't obtain correct file"
            return status
        _writeFileToLocal(name, contents)
        return status
    return status

def listDir(name):
    enc_dirs, key = _getEncryptedFilePath(name)
    data = {'username': CURRENT_USER,
            'action': 'ls',
            'dirname': enc_dirs}
    
    signature = sign_inner_dictionary(USER_PRK, data)
    
    msg = json.dumps({'username': CURRENT_USER,
           'signature': signature,
           'data': data})
    
    response = _transmitToServer(msg)
    respdata = json.loads(response) #json.loads(decrypt(rsa_key.exportKey('PEM'), response))

    ls_contents = []
    key, cipher = _getAESCipher(key)
    for f in respdata['contents']:
        ls_contents.append(_decryptAES(cipher, f))
        
    resp = {
        'status': respdata['status'],
        'message': respdata['message'],
        'dir-list': ls_contents
    }
    return resp

def setPerm(obj, perm, users):
    enc_dirs, key = _getEncryptedFilePath(obj)
    print "read perm: " , obj
    print "enc_dirs: ", enc_dirs
    data = {'username': CURRENT_USER,
            'action': 'read_acl',
            'pathname': enc_dirs}
    
    signature = sign_inner_dictionary(USER_PRK, data)
    
    msg = json.dumps({'username': CURRENT_USER,
           'signature': signature,
           'data': data})
    
    response = _transmitToServer(msg)
    respdata = json.loads(response) #json.loads(decrypt(rsa_key.exportKey('PEM'), response))
    print "data: ", respdata
    acl = respdata['data']['acl']
    for u in users:
        entry = {'perm': [], 'shared_key': None}
        if perm == 'r': 
            entry['perm'] = ['1', '0']
        elif perm == 'rw':
            entry['perm'] = ['1', '1']
        elif perm == 'w':
            entry['perm'] = ['1', '1']

        key_msg = {'username': CURRENT_USER, 
                   'data': {'action': 'key',
                            'username': u }}
        key_sig = sign_inner_dictionary(USER_PRK, key_msg['data'])
        key_msg['signature'] = key_sig
        resp = json.loads(_transmitToServer(json.dumps(key_msg)))
        public_key = RSA.construct((resp['data']['public_key']['N'],
                                   long(resp['data']['public_key']['e'])))
        entry['shared_key'] = encrypt(public_key, key)
        acl[u] = entry

    acl_data = {'username': CURRENT_USER,
                'action': 'write_acl',
                'pathname': enc_dirs,
                'acl': acl,
                'signature_acl': sign_inner_dictionary(USER_PRK, acl)}
    write_msg = json.dumps({'username': CURRENT_USER, 
                            'signature': sign_inner_dictionary(USER_PRK, acl_data),
                            'data': acl_data})
    write_resp = json.loads(_transmitToServer(write_msg))
    return write_resp

def changeDirectory(name):
    dir_list = _buildDirectoryNames(name)
    
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
    global CURRENT_DIRECTORY, CURRENT_DIRECTORY_SK
    global CURRENT_PATH
    if (dr == '..' and len(CURRENT_DIRECTORY) > 0):
        del CURRENT_DIRECTORY[-1]
        del CURRENT_DIRECTORY_SK[-1]
        CURRENT_PATH = os.path.dirname(CURRENT_PATH)
    else:
        current_sk = CURRENT_DIRECTORY_SK[-1]
        key, cipher = _getAESCipher(currenk_sk)
        CURRENT_PATH = os.path.join(CURRENT_PATH, dr)
        dr = _encryptAES(cipher, dr)
        CURRENT_DIRECTORY.append(dr)
        CURRENT_DIRECTORY_SK.append(_getSharedKey(CURRENT_DIRECTORY))
        
def readFileContents(name):
    dirs = _buildDirectoryNames(name)
    print "dirs: ", dirs
    if dirs[0] == "":
        name = os.path.join(CURRENT_PATH, name)
    print "name: ", name
    print "currpath: ", CURRENT_PATH
    filename = os.path.join(HOME_DIRECTORY, name)
    print "filename: ", filename
    file_contents = ""
    if (os.path.isfile(filename)):
        f = open(filename, 'r')
        file_contents = f.read()
        f.close()
    return file_contents

def readAclContents(name):
    dirs = _buildDirectoryNames(name)
    if dirs[0] == "":
        name = os.path.join(CURRENT_PATH, name)
    filename = os.path.join(HOME_DIRECTORY, name)
    contents = ""
    if (os.path.isfile(filename)):
        f = open(filename, 'r')
        contents = f.read()
        f.close()
    return contents

def _writeFileToLocal(filename, contents):
    dirs = _buildDirectoryNames(filename)
    if (dirs[0] == ''):
        filename = os.path.join(CURRENT_PATH, filename)

    f = open(os.path.join(HOME_DIRECTORY, filename), 'w')
    f.write(contents)
    f.close
    
def _getEncryptedFilePath(name):
    dir_list = _buildDirectoryNames(name)
    shared_keys = []
    encr_dirs = []
    current_sk = None
    if (dir_list[0] == '/'):
        current_enc_dir = dir_list[1]
        current_sk = _getSharedKey([current_enc_dir])
        dir_list = dir_list[2:]
        encr_dirs.append(current_enc_dir)
    else:
        current_sk = CURRENT_DIRECTORY_SK[-1]
        # print "current shared key: ", current_sk
        dir_list = dir_list[1:]
        encr_dirs = list(CURRENT_DIRECTORY)        
    print "file path 1: ", encr_dirs
    for dirname in dir_list:

        key, cipher = _getAESCipher(current_sk)
        enc_dir = _encryptAES(cipher, dirname)
        encr_dirs.append(enc_dir)
        if (dirname != dir_list[-1]):
            current_sk = _getSharedKey(encr_dirs)
        print "dirname: ", dirname
        print "file path 2: ", encr_dirs

    return (encr_dirs, current_sk)

def _getSharedKey(dirname):
    data = {'action': 'filekey',
            'dirname': dirname}

    signature = sign_inner_dictionary(USER_PRK, data)

    msg = json.dumps({
        'username': CURRENT_USER,
        'signature': signature,
        'data': data })
    resp = json.loads(_transmitToServer(msg))
    # return decrypt(USER_PRK, resp['shared_key'])
    # print "get shared key: ", resp['data']['filekey']
    return decrypt(USER_PRK, resp['data']['filekey'])
    
def _buildDirectoryNames(name):
    print 'begin build'
    dirs = []
    parent = name
    while parent != "" and parent != "/":
        print parent
        dirs.insert(0, os.path.basename(parent))
        parent = os.path.dirname(parent)
    dirs.insert(0, parent)
    return dirs

def _transmitToServer(text):
    with EFSConnection(HOST, PORT) as c:
        # if (not SERVER_PK):
        #     c.transmit_plaintext(text)
        # else:
        #     c.transmit_encrypted(SERVER_PK, text)
        c.transmit_plaintext(text)
        resp = c.receive(8192)
        return resp

def _initLocalStorage():
    userdir = os.path.join(HOME_DIRECTORY, CURRENT_USER)
    if not os.path.exists(userdir):
        os.makedirs(userdir)
    filename = os.path.join(userdir, CURRENT_USER + "_%s_key.pem")
    f = open(filename % 'public', 'w')
    f.write(USER_PK.exportKey('PEM'))
    f.close()
    
    f = open(filename % 'private', 'w')
    f.write(USER_PRK.exportKey('PEM'))
    f.close()
    
    server_pub = os.path.join(userdir, 'server_pk.pem')
    f = open(server_pub, 'w')
    f.write(SERVER_PK.exportKey('PEM'))
    f.close()
    
def _getServerPublicKey():
    global SERVER_PK
    # print "home: ", HOME_DIRECTORY, " current user: ", CURRENT_USER
    userdir = os.path.join(HOME_DIRECTORY, CURRENT_USER)
    # print "userdir: ", userdir
    server_pub = os.path.join(userdir, 'server_pk.pem')
    # print server_pub
    f = open(server_pub, 'r')
    SERVER_PK = RSA.importKey(f.read())
    f.close()

def _getUserPublicKey(username):
    global USER_PK
    userdir = os.path.join(HOME_DIRECTORY, username)
    filename = os.path.join(userdir, username + '_public_key.pem')
    f = open(filename, 'r')
    key = RSA.importKey(f.read())
    f.close()
    USER_PK = key

def _getUserPrivateKey(username):
    global USER_PRK
    userdir = os.path.join(HOME_DIRECTORY, username)
    filename = os.path.join(userdir, username + '_private_key.pem')
    f = open(filename, 'r')
    key = RSA.importKey(f.read())
    f.close()
    USER_PRK = key

def _padString(s):
    return s + ((BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE))

def _unPad(s):
    return s[:-ord(s[len(s)-1:])]

def _getAESCipher(key=None):
    if (key == None): 
        key = base64.b64encode(Random.new().read(32))
    cipher = AES.new(base64.b64decode(key))
    # print "AES cipher key is", key
    return (key, cipher)

def _encryptAES(cipher, plaintext):
    return base64.b64encode(cipher.encrypt(_padString(plaintext)))

def _decryptAES(cipher, ciphertext):
    return _unPad(cipher.decrypt(base64.b64decode(ciphertext)).decode('utf-8'))
    