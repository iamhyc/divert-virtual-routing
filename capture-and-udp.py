#! /usr/bin/python
'''
Sniff and UDP.py
@author: Mark Hong
@level: debug
'''
import socket, Queue, threading
from Utility import *
import pydivert

global w
DBG = 0

def runThread(pkt_q):
	global count, length
	while True:
		if not pkt_q.empty():
			raw = pkt_q.get()
			packet = str(bytearray(raw))
			#print("%d\t%s"%(len(packet), packet))
			skt.sendto(packet, ('localhost', 12345))

			count += 1
			length += len(packet)
			remains = pkt_q.qsize()
			print("%d\t%d\t%.2f MB"%(count, remains, length/1E6))
			pass
		pass
	pass

def main():
	global flt_ctrl, w
	w = pydivert.WinDivert(flt_ctrl)
	w.open()
	while True:
		packet = w.recv(bufsize=1500)
		w.send(packet)
		pkt_q.put(packet.raw)
		pass
	pass

def init():
	global skt, count, length, pkt_q, flt_ctrl
	count = 0
	length = 0

	##init parameter from json
	config = load_json('./config.json')
	iface_t = get_iface(config['cap_iface'])

	iface_ctrl = "inbound and ifIdx==%d and subIfIdx==%d"%(iface_t)
	src_ctrl = "ip.SrcAddr==%s"%(config["src_host"])
	dst_ctrl = "ip.DstAddr>=%s and ip.DstAddr<=%s"%(config["dst_host"][0], config["dst_host"][-1])
	test_ctrl = "not tcp.DstPort==11112"

	if DBG:
		flt_ctrl = '%s and %s and %s or %s'%(iface_ctrl, src_ctrl, dst_ctrl, test_ctrl)
	else:
		flt_ctrl = '%s and %s and %s'%(iface_ctrl, src_ctrl, dst_ctrl)
		pass
	#flt_ctrl = '%s and %s'%(iface_ctrl, test_ctrl) #for test
	#print(flt_ctrl) #for debug
	##socket & thread init
	skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	pkt_q = Queue.Queue()
	runHandle = threading.Thread(target=runThread, args=(pkt_q, ))
	runHandle.setDaemon(True)
	runHandle.start()
	pass

if __name__ == '__main__':
	init()
	try:
		main()
	except Exception as e:
		printh("CapMain", e, 'red') #for debug
		w.close()
		pass
