import client
import sys
sys.path.insert(0, '/home/henchill/Documents/Workspace/encrypted_file_system/server')

from server import *
from encrypt import *

if __name__ == "__main__":
 
    resp1 = client.register('aakriti')
    resp2 = client.register('henchill')
    
    print 'create aakriti: ', resp1
    print 'create henchill: ', resp2
    
    
