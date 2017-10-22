#! /usr/bin/python

import socket

udp_setup = ('localhost', 11112)

def main():
	skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	while True:
		cmd = raw_input("Please input a string:")
		skt.sendto(cmd, udp_setup)
		pass
	pass

if __name__ == '__main__':
	main()