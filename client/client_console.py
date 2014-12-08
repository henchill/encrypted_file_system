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
HOST = 'localhost'
PORT = 1027

server_public = None
current_directory = ''
base_directory = None

# User-specific
current_user = None

# Encryption details
chunk_size = 200

# Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.settimeout(1)

home = os.path.join(os.environ['HOME'], 'encrypted_file_system')

helptext = """ Coming Soon  """

def dispatch(cmd, args):
    global current_directory, server_public, current_user

    # REGISTER
    if cmd == "register":
        if len(args) > 1:
            print "Too many arguments for command register"
        elif (len(args) == 0):
            print "Please specify a username"
        else:
            resp, server_public, current_user = client.register(s, args[0])
            if resp['status'] == 'error': 
                print "Failed to register user. %s" % resp['message']
            else:
                if not os.path.exists(home):
                    os.makedirs(home)
                print "Account created. Welcome, %s" % current_user.username
    elif cmd == "create-file":
        if len(args) == 0:
            print "Please specify a name for the file"
        elif len(args) > 1:
            print "Incorrect arguments for command create-file"
        else:
            filename = args[0]
            resp = client.createFile(filename)
            if (resp['status'] == 'error'):
                print "Failed to create file -- %s" % resp['message']
            else:
                fd = os.open(os.path.join(base_directory, filename),    
                             os.O_RDWR|os.O_CREAT)
                os.close(fd)
                print "Successfully created file %s" % filename
    elif cmd == "create-directory":
        if len(args) == 0:
            print "Please specify a directory name"
        elif len(args) > 1:
            print "Incorrect arguments for command create-directory"
        else:
            directory = args[0]
            resp = client.createDirectory(directory)
            if (resp['status'] == 'error'):
                print "Failed to create file -- %s " % resp['message']
            else:
                os.path.makedirs(os.path.join(base_directory, directory)
                print "Successfully created directory %s" % directory
    elif cmd == "write-file":
        pass
    elif cmd == 
            


try:
    while True:
        try:
            user_input = raw_input("tefs> ")
            cmd = user_input.split(' ')[0]
            args = user_input.split(' ')[1:]
            if cmd == "quit":
                print "Bye"
                break
            else:
                dispatch(cmd, args)
        except socket.timeout as st:
            print "(socket) timeout"
            continue
        except (ValueError, KeyboardInterrupt) as e:
            print e
            continue
except EOFError as e:
    print "\nBye"
except Exception as e:
    raise
finally:
    s.close()
