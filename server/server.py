#!/usr/bin/env python2.7

import time
import socket
import threading
import SocketServer

buffer_size = 1024
host = "localhost"
servername = "efs-server"
port = 1025

use_threaded = False

class EFSTCPHandler(SocketServer.BaseRequestHandler):
	def handle(self):
		data = self.request.recv(buffer_size)
		if use_threaded:
			cur_thread = threading.current_thread()
			response = "{} responds, {}".format(cur_thread.name, data)
		else:
			response = "Responding, {}".format(data)
		print response
		self.request.sendall(response)

if __name__ == "__main__":
	if use_threaded:
		server = SocketServer.ThreadingTCPServer((host, port), EFSTCPHandler)

		server_thread = threading.Thread(target=server.serve_forever, name=servername)
		server_thread.daemon = True
		server_thread.start()
	else:
		server = SocketServer.TCPServer((host, port), EFSTCPHandler)

	print "Server is running..."

	server.serve_forever()
