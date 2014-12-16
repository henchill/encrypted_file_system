#!/usr/bin/env python2.7

import os
import sys
import stat
import errno

import json
import base64

sys.path.insert(0, '../server')
from encrypt import *
from transmit import *

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random

from fuse import FUSE, FuseOSError, Operations

rsa_key_size = 2048 # bits
aes_key_size = 16   # bytes

host = "localhost"
port = 1025

class ParanoiaFUSE(Operations):
    def __init__(self, username, keyfile):
        self.username = username

        if not keyfile:
            self.key = RSA.generate(rsa_key_size)
            with open(username + ".pem", "w") as keyfile:
                keyfile.write(self.key.exportKey("PEM"))
            print "[key generated and saved to %s.pem]" % username
            self._register()
        else:
            with open(keyfile, "r") as key:
                self.key = RSA.importKey(key.read())
            print "[key loaded from %s]" % keyfile

        self._get_server_key()
        self.fd = 0
        self.files = []

    # Helpers
    # =======

    def _plain_acl(self):
        rsa_key = self.key
        public_key = rsa_key.publickey()
        aes_key = self._new_AES_key()

        acl = {self.username: {"perm": ["1", "1"],
                               "shared_key": encrypt(rsa_key, aes_key)}}
        return acl

    def _new_AES_key(self):
        aes_key = base64.b64encode(Random.get_random_bytes(aes_key_size))[:aes_key_size]
        # print "[generated %s as aes_key]" % aes_key
        return aes_key

    def _register(self):
        acl = self._plain_acl()

        rsa_key = self.key
        public_key = self.key.publickey()

        register_data = {"username": self.username,
                         "action": "register",
                         "public_key": {"N": public_key.n,
                                        "e": public_key.e},
                         "acl": acl,
                         "signature_acl": sign_inner_dictionary(rsa_key, acl)}

        signature_register_data = sign_inner_dictionary(rsa_key, register_data)

        register = {"username": self.username,
                    "signature": signature_register_data,
                    "data": register_data}

        with EFSConnection(host, port) as c:
            c.transmit_plaintext(json.dumps(register))
            response = json.loads(c.receive(8192))

        if response["status"] == "OK":
            print "[registered user %s]" % self.username
        else:
            print "Error, server says:", response["message"]

    def _get_server_key(self):
        rsa_key = self.key
        server_key = {"username": self.username,
                      "data": {"action": "key",
                               "username": "server"}}
        server_key_signature = sign_inner_dictionary(rsa_key, server_key["data"])
        server_key["signature"] = server_key_signature

        with EFSConnection(host, port) as c:
            c.transmit_plaintext(json.dumps(server_key))
            response = json.loads(c.receive(8192))

        if response["status"] == "OK":
            N = long(response["data"]["public_key"]["N"])
            e = long(response["data"]["public_key"]["e"])
            self.server_key = RSA.construct((N, e))
            print "[got server key]"
        else:
            print "Error, server says:", response["message"]

    def _encrypt_path(self, path):
        # Create directory array
        directories = []
        parent = path
        while parent != "" and parent != "/":
            directories.insert(0, os.path.basename(parent))
            parent = os.path.dirname(parent)
        directories.insert(0, parent)

        # print "before sorting:", directories

        if directories == ["/"]:
            return directories      # Just root (not encrypted)
        elif len(directories) == 2: # Root and a name
            return directories[1:2] # Just the name (not encrypted)

        del directories[0] # Remove root
        # print "after edge cases:", directories
        # If more than root, will need to decrypt directories as we go

        for i in xrange(1, len(directories)):
            partial_directory = directories[:i]
            filekey = self._get_file_key(partial_directory)
            # print "get_file_key", partial_directory, "is", filekey
            encrypted_partial = encrypt_aes(filekey, directories[i])
            directories[i] = encrypted_partial

        # print "keys obtained, should be encrypted:", directories

        return directories

    def _get_file_key(self, path):
        """Gets the file key for an encrypted path."""
        if path == ["/"]:
            return None

        filekey_data = {"action": "filekey",
                        "dirname": path}

        signature_filekey_data = sign_inner_dictionary(self.key, filekey_data)

        filekey = {"username": self.username,
                   "signature": signature_filekey_data,
                   "data": filekey_data}

        with EFSConnection(host, port) as c:
            c.transmit_plaintext(json.dumps(filekey))
            response = json.loads(c.receive(8192))

        if not response["status"] == "OK":
            print "Error, server says:", response["message"]
            return None

        return decrypt(self.key, response["data"]["filekey"])

    # Filesystem methods
    # ==================

    def access(self, path, mode):
        # print "access %s" % path
        pass

    def chmod(self, path, mode):
        full_path = path
        return os.chmod(full_path, mode)

    def chown(self, path, uid, gid):
        full_path = path
        return os.chown(full_path, uid, gid)

    def getattr(self, path, fh=None):
        encrypted_path = self._encrypt_path(path)

        getattr_data = {"username": self.username,
                        "action": "getattr",
                        "filename": encrypted_path}

        getattr_signature = sign_inner_dictionary(self.key, getattr_data)

        getattr = {"username": self.username,
                   "signature": getattr_signature,
                   "data": getattr_data}

        with EFSConnection(host, port) as c:
            c.transmit_plaintext(json.dumps(getattr))
            response = json.loads(c.receive(8192))

        if response["status"] == "OK":
            return response["data"]
        else:
            print "Error, server says:", response["message"]
            raise FuseOSError(errno.ENOENT)

        attr = {"st_atime": 0,
                "st_ctime": 0,
                "st_gid": 0,
                "st_mode": 0,
                "st_mtime": 0,
                "st_nlink": 0,
                "st_size": 0,
                "st_uid": 0}
        return attr

    def readdir(self, path, fh):
        encrypted_path = self._encrypt_path(path)

        # print "listing encrypted_path=", encrypted_path

        dirents = ['.', '..']

        listing_data = {"username": self.username,
                        "action": "ls",
                        "dirname": encrypted_path}

        listing_signature = sign_inner_dictionary(self.key, listing_data)

        listing = {"username": self.username,
                   "signature": listing_signature,
                   "data": listing_data}

        with EFSConnection(host, port) as c:
            c.transmit_plaintext(json.dumps(listing))
            response = json.loads(c.receive(8192))

        if response["status"] == "OK":
            # print "[got response from server]:", response["data"]
            encrypted_dirents = response["data"]["contents"]
        else:
            print "Error, server says:", response["message"]

        # print "edirents = ", encrypted_dirents

        if len(path) == 1 and path[0] == "/":
            dirents += encrypted_dirents # not actually encrypted
        else:
            filekey = self._get_file_key(encrypted_path)
            # print "filekey for %s is %s" % (encrypted_path, filekey)
            for encrypted_dirent in encrypted_dirents:
                dirents.append(decrypt_aes(filekey, encrypted_dirent))

        for r in dirents:
            yield r

    def readlink(self, path):
        pathname = os.readlink(self._full_path(path))
        if pathname.startswith("/"):
            # Path name is absolute, sanitize it.
            return os.path.relpath(pathname, self.root)
        else:
            return pathname

    def mknod(self, path, mode, dev):
        return os.mknod(self._full_path(path), mode, dev)

    def rmdir(self, path):
        full_path = path
        return os.rmdir(full_path)

    def mkdir(self, path, mode):
        encrypted_path = self._encrypt_path(path)

        # print "encrypted_path =", encrypted_path

        acl = self._plain_acl()
        signature_acl = sign_inner_dictionary(self.key, acl)

        mkdir_data = {"username": self.username,
                      "action": "mkdir",
                      "dirname": encrypted_path,
                      "acl": acl,
                      "signature_acl": signature_acl}

        mkdir_signature = sign_inner_dictionary(self.key, mkdir_data)

        mkdir = {"username": self.username,
                 "signature": mkdir_signature,
                 "data": mkdir_data}

        with EFSConnection(host, port) as c:
            c.transmit_plaintext(json.dumps(mkdir))
            response = json.loads(c.receive(8192))

        if response["status"] == "OK":
            return 0
        else:
            print "Error, server says:", response["message"]
            return -1

    def statfs(self, path):
        full_path = path
        stv = os.statvfs(full_path)
        return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
            'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag',
            'f_frsize', 'f_namemax'))

    def unlink(self, path):
        return os.unlink(self._full_path(path))

    def symlink(self, target, name):
        return os.symlink(self._full_path(target), self._full_path(name))

    def rename(self, old, new):
        return os.rename(self._full_path(old), self._full_path(new))

    def link(self, target, name):
        return os.link(self._full_path(target), self._full_path(name))

    def utimens(self, path, times=None):
        return os.utime(self._full_path(path), times)

    # File methods
    # ============

    def open(self, path, flags):
        full_path = path
        return os.open(full_path, flags)

    def create(self, path, mode, fi=None):
        full_path = path
        print "[creating full_path=%s]" % full_path
        return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)

    def read(self, path, length, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        return os.read(fh, length)

    def write(self, path, buf, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        return os.write(fh, buf)

    def truncate(self, path, length, fh=None):
        full_path = path
        with open(full_path, 'r+') as f:
            f.truncate(length)

    def flush(self, path, fh):
        return os.fsync(fh)

    def release(self, path, fh):
        return os.close(fh)

    def fsync(self, path, fdatasync, fh):
        return self.flush(path, fh)


def main(username, mountpoint, keyfile):
    FUSE(ParanoiaFUSE(username, keyfile), mountpoint, foreground=True)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print "Usage: %s username mountpoint [keyfile]" % sys.argv[0]
        sys.exit(1)

    username = sys.argv[1]
    mountpoint = sys.argv[2]
    keyfile = None

    if len(sys.argv) == 4:
        keyfile = sys.argv[3]

    main(username, mountpoint, keyfile)

