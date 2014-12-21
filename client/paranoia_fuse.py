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

        try:
            if not keyfile:
                keyfile = username + ".pem"
            with open(keyfile, "r") as key:
                self.key = RSA.importKey(key.read())
            print "[key loaded from %s]" % keyfile
        except IOError as e:
            self.key = RSA.generate(rsa_key_size)
            with open(username + ".pem", "w") as keyfile:
                keyfile.write(self.key.exportKey("PEM"))
            print "[key generated and saved to %s.pem]" % username
            self._register()

        self._get_server_key()
        self.fd = 3
        self.files = [None, None, None]

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
            print "[_register] Error, server says:", response["message"]

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
            print "[_get_server_key] Error, server says:", response["message"]

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
            print "[_get_file_key] Error, server says:", response["message"]
            return None

        return decrypt(self.key, response["data"]["filekey"])

    def _exists(self, path):
        """Checks the existence of the given (encrypted) path."""
        exists_data = {"action": "exists",
                       "filename": path}

        signature_exists_data = sign_inner_dictionary(self.key, exists_data)

        exists = {"username": self.username,
                  "signature": signature_exists_data,
                  "data": exists_data}

        with EFSConnection(host, port) as c:
            c.transmit_plaintext(json.dumps(exists))
            response = json.loads(c.receive(8192))

        if not response["status"] == "OK":
            return False

        return response["data"]["exists"]


    # Filesystem methods
    # ==================

    # def access(self, path, mode):
    #     print "access %s" % path
    #     pass

    # def chmod(self, path, mode):
    #     full_path = path
    #     return os.chmod(full_path, mode)

    # def chown(self, path, uid, gid):
    #     full_path = path
    #     return os.chown(full_path, uid, gid)

    def getattr(self, path, fh=None):
        encrypted_path = self._encrypt_path(path)

        getattr_data = {"username": self.username,
                        "action": "getattr",
                        "filename": encrypted_path}

        getattr_signature = sign_inner_dictionary(self.key, getattr_data)

        getattr = {"username": self.username,
                   "signature": getattr_signature,
                   "data": getattr_data}

        filekey = self._get_file_key(encrypted_path)

        with EFSConnection(host, port) as c:
            c.transmit_plaintext(json.dumps(getattr))
            response = json.loads(c.receive(8192))

        if response["status"] == "OK":
            attr = response["data"]
        else:
            print "[getattr] Error, server says:", response["message"]
            raise FuseOSError(errno.ENOENT)

        # Special cases for file types
        if stat.S_ISREG(attr["st_mode"]):
            # Decrypt file length
            attr["st_size"] = int(decrypt_aes(filekey, attr["st_size"]))

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
            print "[readdir] Error, server says:", response["message"]

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

    def _remove(self, path):
        encrypted_path = self._encrypt_path(path)

        remove_data = {"username": self.username,
                       "action": "remove",
                       "filename": encrypted_path}

        remove_signature = sign_inner_dictionary(self.key, remove_data)

        remove = {"username": self.username,
                  "signature": remove_signature,
                  "data": remove_data}

        with EFSConnection(host, port) as c:
            c.transmit_plaintext(json.dumps(remove))
            response = json.loads(c.receive(8192))

        if response["status"] == "OK":
            return 0
        else:
            print "[_remove] Error, server says:", response["message"]
            return -1

    def rmdir(self, path):
        return self._remove(path)

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
            print "[mkdir] Error, server says:", response["message"]
            return -1

    # def statfs(self, path):
    #     full_path = path
    #     stv = os.statvfs(full_path)
    #     return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
    #         'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag',
    #         'f_frsize', 'f_namemax'))

    def rename(self, old, new):
        print "renaming %s to %s" % (old, new)


        attr = self.getattr(old)
        size = attr["st_size"]

        oldfile = self.open(old, os.O_RDONLY)
        oldfile_contents = self.read(old, size, 0, oldfile)

        newfile = self.open(new, os.O_CREAT | os.O_WRONLY)
        self.write(new, oldfile_contents, 0, newfile)

    # def utimens(self, path, times=None):
    #     print "utimens, path=", path
    #     pass

    # File methods
    # ============

    def _create(self, path):
        acl = self._plain_acl()
        signature_acl = sign_inner_dictionary(self.key, acl)

        encrypted_filekey = acl[self.username]["shared_key"]
        filekey = decrypt(self.key, encrypted_filekey)
        encrypted_empty_string = encrypt_aes(filekey, "")
        encrypted_length = encrypt_aes(filekey, "0")

        create_data = {"username": self.username,
                       "action": "create",
                       "filename": path,
                       "file": encrypted_empty_string,
                       "length": encrypted_length,
                       "acl": acl,
                       "signature_acl": signature_acl}

        create_signature = sign_inner_dictionary(self.key, create_data)

        create = {"username": self.username,
                  "signature": create_signature,
                  "data": create_data}

        with EFSConnection(host, port) as c:
            c.transmit_plaintext(json.dumps(create))
            response = json.loads(c.receive(8192))

        return response["status"] == "OK"

    def open(self, path, flags):
        encrypted_path = self._encrypt_path(path)

        exists = self._exists(encrypted_path)

        if not self._exists(encrypted_path):
            if (flags & os.O_CREAT):
                self._create(encrypted_path)
            else:
                raise FuseOSError(errno.ENOENT)

        this_fd = self.fd
        self.fd += 1

        this_file = {"encrypted_path": encrypted_path}

        self.files.insert(this_fd, this_file)
        return this_fd

    def create(self, path, mode, fi=None):
        print "create, path=", path
        create_flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC
        return self.open(path, create_flags)

    def _read_into_self(self, path, fh):
        encrypted_path = self._encrypt_path(path)

        read_data = {"username": self.username,
                     "action": "read",
                     "filename": encrypted_path}

        read_signature = sign_inner_dictionary(self.key, read_data)

        read = {"username": self.username,
                "signature": read_signature,
                "data": read_data}

        with EFSConnection(host, port) as c:
            c.transmit_plaintext(json.dumps(read))
            response = json.loads(c.receive(8192))

        if response["status"] == "OK":
            encrypted_contents = response["data"]["file"]
            self.files[fh]["encrypted_contents"] = encrypted_contents

    def read(self, path, length, offset, fh):
        print "read, path=", path, "offset=", offset, "length=", length
        if not "encrypted_contents" in self.files[fh]:
            self._read_into_self(path, fh)

        encrypted_contents = self.files[fh]["encrypted_contents"]
        encrypted_path = self._encrypt_path(path)
        filekey = self._get_file_key(encrypted_path)
        decrypted_contents = decrypt_aes(filekey, encrypted_contents)
        print "decrypted contents is:", decrypted_contents[offset:offset+length]
        return decrypted_contents[offset:offset+length]

    def write(self, path, buf, offset, fh):
        print "write, path=", path
        encrypted_path = self._encrypt_path(path)

        if not "encrypted_contents" in self.files[fh]:
            self._read_into_self(path, fh)

        encrypted_contents = self.files[fh]["encrypted_contents"]
        filekey = self._get_file_key(encrypted_path)
        decrypted_contents = decrypt_aes(filekey, encrypted_contents)

        before = decrypted_contents[:offset]
        after = decrypted_contents[offset+len(buf):]
        new_contents = before + buf + after

        filekey = self._get_file_key(encrypted_path)

        encrypted_new_contents = encrypt_aes(filekey, new_contents)
        encrypted_length = encrypt_aes(filekey, str(len(new_contents)))

        write_data = {"username": self.username,
                      "action": "write",
                      "filename": encrypted_path,
                      "file": encrypted_new_contents,
                      "length": encrypted_length}

        write_signature = sign_inner_dictionary(self.key, write_data)

        write = {"username": self.username,
                 "signature": write_signature,
                 "data": write_data}

        with EFSConnection(host, port) as c:
            c.transmit_plaintext(json.dumps(write))
            response = json.loads(c.receive(8192))

        if response["status"] == "OK":
            return len(buf)
        return 0

    # def truncate(self, path, length, fh=None):
    #     print "truncate, path=", path
    #     full_path = path
    #     with open(full_path, 'r+') as f:
    #         f.truncate(length)

    # def flush(self, path, fh):
    #     print "flush, path=", path
    #     encrypted_path = self._encrypt_path(path)
    #     encrypted_contents = self.files[fh]["encrypted_contents"]

    #     write_data = {"username": self.username,
    #                   "action": "write",
    #                   "filename": encrypted_path,
    #                   "file": encrypted_contents}

    #     write_signature = sign_inner_dictionary(self.key, write_data)

    #     write = {"username": self.username,
    #              "signature": write_signature,
    #              "data": write_data}

    #     with EFSConnection(host, port) as c:
    #         c.transmit_plaintext(json.dumps(write))
    #         response = json.loads(c.receive(8192))

    #     if response["status"] == "OK":
    #         pass
    #     else:
    #         print "Error, server says:", response["message"]

    # def release(self, path, fh):
    #     print "release, path=", path

    # def fsync(self, path, fdatasync, fh):
    #    print "fsync, path=", path

    def unlink(self, path):
        print "unlink, path=", path
        return self._remove(path)


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

