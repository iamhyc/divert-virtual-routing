#! /usr/bin/python
'''
UPD and sendp.py
@author: Mark Hong
@level: debug
'''
import socket
from Utility import *
from scapy.all import *

def init():
	global count, skt, length, l3sock
	skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	skt.bind(('', 12345))
	l3sock = conf.L3socket(iface=conf.iface)
	count = 0
	length = 0
	pass

def main():
	global count, length, l3sock
	while True:
		data, addr = skt.recvfrom(4096)
		length += len(data)

		data = Ether()/IP(data)
		# try:
		# 	data.dport = 11112
		# except Exception as e:
		# 	pass
		l3sock.send(data)
		count += 1
		
		print("%d\t%.2f MB"%(count, length/1E6))
		pass
	pass

if __name__ == '__main__':
	init()
	print(conf.iface)
	main()