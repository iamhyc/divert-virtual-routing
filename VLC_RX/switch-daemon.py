#! /usr/bin/python
'''
UPD and sendp.py
@author: Mark Hong
@level: debug
'''
import socket, time, threading, Queue
from Utility import *
import pydivert, ifaddr

global wdl, wul

def updateThread():
	# update ip map here#
	while True:
		time.sleep(1.0)
		try:
			tmp = load_json('./subnet.json')
			subnet_map = tmp #atom
			pass
		except Exception as e:
			pass
		pass
	pass

def proxy_map(addr, reverse=0):
	global subnet_map
	tmp = subnet_map #atom
	if reverse:
		remap = tmp.keys()[tmp.values().index()]
		return remap
	else:
		remap = tmp.values()[tmp.keys().index()]
		return remap
	pass

def runThreadUL():
	global wul, iface_ul
	printh("UL-Thread", "Now on %s"%(iface_ul), "green")
	while True:
		packet = wul.recv(bufsize=1500)
		packet.dst_addr = proxy_map(packet.dst_addr, 0)
		wul.send(packet, recalculate_checksum=True)
		pass
	pass

def runThreadDL(pkt_q):
	global wdl, iface_dl, count, length
	print("DL-Thread", "Now on %s"%(iface_dl), "green")
	while True:
		if not pkt_q.empty():
			packet = pkt_q.get()
			packet.dst_addr = proxy_map(packet.dst_addr, 1)
			wdl.send(packet)
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
			#packet.dst_port = 11112 #for test
			pkt_q.put(packet)
		except Exception as e:
			pass#try(skt)
		pass#while
	pass

def init():
	global count, skt, length, pkt_q, subnet_map
	global wdl, wul, iface_ul, iface_dl,
	count = 0
	length = 0
	subnet_map = {}

	config = load_json('./config.json')
	iface_ul = config["iface_ul"]
	iface_dl = config["iface_dl"]

	##WinDivert Setup
	flt_dl = ("%s and IfIdx==%d and SubIfIdx==%d"
				%("inbound", iface_dl))
	wdl = pydivert.WinDivert(filter=flt_dl)
	wdl.open() ##closer to `miniport`
	flt_ul = ("%s and IfIdx==%d and SubIfIdx==%d not %s"
				%("outbound", iface_ul, config["exFilter"]))
	wul = pydivert.WinDivert(flt_ul)
	wul.open() ##closer to `protocol`

	##Socket Setup
	skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	skt.bind(('', 12345))
	skt.setblocking(False)
	pkt_q = Queue.Queue()

	##Threading init
	runHandleUL = threading.Thread(target=runThreadUL)
	runHandleUL.setDaemon(True)
	runHandleUL.start()
	runHandleDL = threading.Thread(target=runThreadDL, args=(pkt_q, ))
	runHandleDL.setDaemon(True)
	runHandleDL.start()
	updateHandle = threading.Thread(target=updateThread)
	updateHandle.setDaemon(True)
	updateHandle.start()
	pass

if __name__ == '__main__':
	init()
	try:
		printh("SendMain", "Now on %s"%(str(iface_t)), "green")
		main()
	except Exception as e:
		printh("SendMain", e, 'red')
		wdl.close()
		wul.close()