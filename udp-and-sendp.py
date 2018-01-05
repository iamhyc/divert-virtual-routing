#! /usr/bin/python
'''
UPD and sendp.py
@author: Mark Hong
@level: debug
'''
import socket
from scapy.all import *

def init():
	global count, skt
	skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	skt.bind(('', 12345))
	count = 0
	pass

def main():
	global count
	while True:
		data, addr = skt.recvfrom(8192)
		sendp(Ether()/IP(data), iface=conf.iface)
		count += 1
		print(count)
		pass
	pass

if __name__ == '__main__':
	init()
	print(conf.iface)
	main()