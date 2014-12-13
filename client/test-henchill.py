import client
import sys
sys.path.insert(0, '/home/henchill/Documents/Workspace/encrypted_file_system/server')

from server import *
from encrypt import *

if __name__ == "__main__":
 
    resp = client.signIn('henchill')
    print "RESPONSE REGISTER: ", resp

    resp = client.writeFile("/aakriti/test3.txt", "foo/test.txt")
    print "RESPONSE CREATE_FILE3:", resp
    
    # resp = client.writeFile("/aakriti/foo/test.txt", "foo/test.txt")
    # print "RESPONSE CREATE_FILE1: ", resp

    resp = client.readFile("/aakriti/foo/test2.txt")
    print "RESPONSE CREATE_FILE2: ", resp

    
    
