#! /usr/bin/python
'''
UPD and sendp.py
@author: Mark Hong
@level: debug
'''
import socket, threading, Queue
from Utility import *
import pydivert, ifaddr

global w

def runThread(pkt_q):
	global w, count, length
	while True:
		if not pkt_q.empty():
			packet = pkt_q.get()
			w.send(packet)
			remains = pkt_q.qsize()
			print("%d\t%d\t%.2f MB"%(count, remains, length/1E6))
			pass
		pass
	pass

def main():
	global count, length, pkt_q, iface_t
	while True:
		try:
			##raw data from socket
			data, addr = skt.recvfrom(4096)
			length += len(data)
			count += 1
			##packet creation
			v = memoryview(bytearray(data))
			packet = pydivert.Packet(v, 
				iface_t, #Network Interface index & subindex
				pydivert.Direction(1) #0 for OUT_BOUND
				#1 for INBOUND to perform loopback (P.S. insert after inception)
			)
			##packet manipulation
			#packet.dst_port = 11112 #for test
			pkt_q.put(packet)
		except Exception as e:
			pass#try(skt)
		pass#while
	pass

def init():
	global count, skt, length, pkt_q, iface_t, w
	count = 0
	length = 0

	w = pydivert.WinDivert(filter="false")
	w.open()

	config = load_json('./config.json')
	iface_t = get_iface(config['send_iface'])

	skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	skt.bind(('', 12345))
	skt.setblocking(False)
	pkt_q = Queue.Queue()
	runHandle = threading.Thread(target=runThread, args=(pkt_q, ))
	runHandle.setDaemon(True)
	runHandle.start()
	pass

if __name__ == '__main__':
	init()
	try:
		printh("SendMain", "Now on %s"%(str(iface_t)), "green")
		main()
	except Exception as e:
		printh("SendMain", e, 'red')
		w.exit()