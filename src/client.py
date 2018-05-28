import socket
import time
import sys
import struct

HOST = "127.0.0.1"
PORT = 8080
PAYLOAD = struct.pack("I", 12345)

clients = []

for i in range(0, 25):
	client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	client.connect((HOST, PORT))

	client.sendall(PAYLOAD)
	clients.append(client)
	time.sleep(2);

client.close()
