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

efs_server = None

class EFSServer:
	def handle_request(self, request):
		print "I am supposed to handle:", str(request)

	# Your code here

class EFSHandler(SocketServer.BaseRequestHandler):
	def handle(self):
		data = self.request.recv(buffer_size)
		if use_threaded:
			cur_thread = threading.current_thread()
			response = "{} responds, {}".format(cur_thread.name, data)
		else:
			response = "Server responds: {}".format(data)
		efs_server.handle_request(data)
		self.request.sendall(response)

if __name__ == "__main__":
	efs_server = EFSServer()

	if use_threaded:
		server = SocketServer.ThreadingTCPServer((host, port), EFSHandler)

		server_thread = threading.Thread(target=server.serve_forever, name=servername)
		server_thread.daemon = True
		server_thread.start()
	else:
		server = SocketServer.TCPServer((host, port), EFSHandler)

	print "Server is running..."

	try:
		server.serve_forever()
	except KeyboardInterrupt as ki:
		print "Keyboard interrupt"
		server.shutdown()
