#!/usr/bin/env python2.7

import base64
import socket
import json
import re
import client
import os

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto import Random

# Server things

current_directory = ''
base_directory = None

# User-specific
current_user = None

# Encryption details
chunk_size = 200

home = os.path.join(os.environ['HOME'], 'encrypted_file_system')

helptext = """ Coming Soon  """

def verifyArgs(command, target, args_len):
    if (args_len < target):
        print "Too few arguments provided for command %s" % command
        print "Type 'help %s' for more information" % command
        return False
    elif (args_len > target):
        print "Too many arguments provided for command %s" % command
        print "Type 'help %s' for more information" % command
        return False
    else:
        return True
def dispatch(cmd, args):
    global current_user, current_directory
    
    # REGISTER
    if cmd == "register":
        if len(args) > 1:
            print "Too many arguments for command register"
        elif (len(args) == 0):
            print "Please specify a username"
        else:
            resp = client.register(args[0])
            if resp['status'] == 'error': 
                print "Failed to register user. %s" % resp['message']
            else:
                current_user = args[0]
                print "Account created. Welcome, %s" % current_user
    elif cmd == "create-file":
        if (verifyArgs('create-file', 1, len(args)) or
            verifyArgs('create-file', 2, len(args))):
            filename = args[0]
            data = args[1] if (len(args) == 2) else None
            resp = client.createFile(filename, data)
            if (resp['status'] == 'error'):
                print "Failed to create file -- %s" % resp['message']
            else:
                print "Successfully created file %s" % filename
    elif cmd == "create-directory":
        if (verifyArgs('create-directory', 1, len(args))):
            directory = args[0]
            resp = client.createDirectory(directory)
            if (resp['status'] == 'error'):
                print "Failed to create directory -- %s " % resp['message']
            else:
                print "Successfully created directory %s" % directory
    elif cmd == "write-file":
        if (verifyArgs('write-file', 1, len(args)) or
            verifyArgs('write-file', 2, len(args))):
            filename = args[0]
            data = args[1] if (len(args) == 2) else None
            resp = client.writeFile(filename, data)
            if (resp['status'] == 'error'):
                print "Failed to write file -- %s" % resp['message']
            else:
                print "Successfully wrote to file %s" % filename
    elif cmd == "rename":
        if (verifyArgs('rename', 2, len(args))):
            resp = client.rename(args[0], args[1])
            if (resp['status'] == 'error'):
                print "Failed to perform rename -- %s" % resp['message']
            else:
                print "Successfully performed rename"            
    elif cmd == "read-file":
        if (verifyArgs('read-file', 1, len(args))):
            resp = client.readFile(args[0])
            if (resp['status'] == 'error'):
                print 'Failed to read file -- %s' % resp['message']
            else:
                print 'File now available in efs local dir'
    elif cmd == "list-dir":
        if (verifyArgs('list-dir', 1, len(args))):
            resp = client.listDir(args[0])
            if (resp['status'] == 'error'):
                print 'Cannot list directory -- %s' % resp['message']
            else:
                for elem in resp['dir-list']:
                    print elem
    elif cmd == "set-perm":
        if (len(args) > 2 and verifyPerm(args[0])):
            resp = client.setPerm(args[1], args[0], args[2:])
            if (resp['status'] == 'error'):
                print 'failed to set permissions'
            else:
                print 'permissions have been set'
    elif cmd == "delete": 
        if (len(args) > 0):
            resp = client.delete(args[0])
            if (resp['status'] == 'error'):
                print "Failed to delete item -- %s" % resp['message']
            else:
                print "Delete was successful"
    elif cmd == "begin": 
        if (verifyArgs('begin', 1, len(args))):
            client.signIn(args[0])
    elif cmd == "change-dir":
        if (verifyArgs('change-dir', 1, len(args))):
            resp = client.changeDirectory(args[0])
            if (resp['status'] == 'success'):
                current_directory = resp['curr_dir']


try:
    while True:
        try:
            user_input = raw_input("tefs/> ")
            cmd = user_input.split(' ')[0]
            args = user_input.split(' ')[1:]
            if cmd == "quit":
                print "Bye"
                break
            else:
                dispatch(cmd, args)
        except (ValueError, KeyboardInterrupt) as e:
            print e
            continue
except EOFError as e:
    print "\nBye"
except Exception as e:
    raise
