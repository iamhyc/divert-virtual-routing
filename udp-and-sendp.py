#! /usr/bin/python
'''
UPD and sendp.py
@author: Mark Hong
@level: debug
'''
import socket, threading, Queue
from Utility import *
from scapy.all import *

def runThread(pkt_q):
	global l3sock, count, length
	while True:
		if not pkt_q.empty():
			data = pkt_q.get()
			l3sock.send(data)
			remains = pkt_q.qsize()
			print("%d\t%d\t%.2f MB"%(count, remains, length/1E6))
			pass
		pass
	pass

def main():
	global count, length, pkt_q
	while True:
		data, addr = skt.recvfrom(4096)
		length += len(data)
		count += 1

		data = Ether()/IP(data)
		# try:
		# 	data.dport = 11112
		# except Exception as e:
		# 	pass
		pkt_q.put(data)
		pass
	pass

def init():
	global count, skt, length, l3sock, pkt_q
	count = 0
	length = 0

	l3sock = conf.L3socket(iface=conf.iface)

	skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	skt.bind(('', 12345))
	pkt_q = Queue.Queue()
	runHandle = threading.Thread(target=runThread, args=(pkt_q, ))
	runHandle.setDaemon(True)
	runHandle.start()
	pass

if __name__ == '__main__':
	init()
	print(conf.iface)
	try:
		main()
	except Exception as e:
		raise e