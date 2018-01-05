#! /usr/bin/python
'''
Sniff and UDP.py
@author: Mark Hong
@level: debug
'''
import socket
from scapy.all import *

def init():
	global count, skt
	skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	count = 0
	pass

def sniff_hook(x):
	global count
	if x.haslayer(IP):
		data = x.getlayer(IP)
		skt.sendto(str(data), ('', 12345))
		pass
	count += 1
	print(count)
	pass

if __name__ == '__main__':
	init()
	print(conf.iface)
	sniff(iface=conf.iface, prn=sniff_hook)
