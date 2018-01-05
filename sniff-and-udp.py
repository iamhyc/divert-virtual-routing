#! /usr/bin/python
'''
Sniff and UDP.py
@author: Mark Hong
@level: debug
'''
import socket, Queue, threading
from Utility import *
from scapy.all import *

def sniff_hook(x):
	global pkt_q
	if x.haslayer(IP):
		packet = x.getlayer(IP)
		pkt_q.put(packet)
		pass
	pass

def runThread(pkt_q):
	global count, length
	while True:
		if not pkt_q.empty():
			packet = pkt_q.get()
			fragments = fragment(packet, fragsize=1024)
			for frag in fragments:
				skt.sendto(str(frag), ('', 12345))
				count += 1
				length += len(frag)
				remains = pkt_q.qsize()
				print("%d\t%d\t%.2f MB"%(count, remains, length/1E6))
				pass
			pass
		pass
	pass

def main():
	global flt_ctrl
	#sniff(iface=conf.iface, filter="not dst port 11112", prn=sniff_hook)
	s = conf.L2socket(type=ETH_P_ALL, iface=conf.iface)
	while True:
		p = s.recv()
		if p is not None:
			sniff_hook(p)
			pass
		pass
	pass

def init():
	global skt, count, length, pkt_q, flt_ctrl
	count = 0
	length = 0

	#init parameter from json
	config = load_json('./config.json')
	src_ctrl = "src host %s"%(config["src_host"])
	dst_ctrl = "dst host %s"%(' '.join(config["dst_host"]))
	flt_ctrl = '%s %s'%(src_ctrl, dst_ctrl)
	# socket & thread init
	skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
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
		pass
