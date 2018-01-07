#! /usr/bin/python
'''
Sniff and UDP.py
@author: Mark Hong
@level: debug
'''
import socket, time, Queue, threading
from Utility import *
import pydivert

global w, iface_t, subnet_map
DBG = 1

def updateThread():
	global subnet_map
	while True:
		time.sleep(1.0)
		try:
			tmp = load_json('./subnet-mapping.json')
			config = tmp #atom
		except Exception as e:
			pass
		pass
	pass

def packet_wrapper(packet):
	global subnet_map
	ipAddr = packet.dst_addr
	ipAddr_raw = socket.inte_aton(ipAddr)
	fraw = str(bytearray(packet.raw))
	fid = ''

	tmp = subnet_map #atom
	for k,v in tmp.items():
		if ipAddr in v['subnet']:
			fid = k
			break
		pass

	packet = struct_helper((ipAddr_raw, fid), fraw)
	return packet

def runThread(pkt_q):
	global count, length
	while True:
		if not pkt_q.empty():
			packet = pkt_q.get()
			udp_packet = str(bytearray(packet.raw))
			#udp_packet = packet_wrapper(packet) #for future use
			skt.sendto(udp_packet, ('localhost', udp_port))

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
		#w.send(packet) #no return to network stack
		pkt_q.put(packet)
		pass
	pass

def init():
	global struct_helper
	global skt, count, length, pkt_q, flt_ctrl, iface_t, udp_port, subnet_map
	count = 0
	length = 0

	##init parameter from json
	config = load_json('./config.json')
	iface_t = get_iface(config['cap_iface'])
	udp_port = config['udp_port']
	struct_helper = StructHelper(config["frame"]) #'IB'=IPAddr+RxID

	subnet_map = {}
	iface_ctrl = "inbound and ifIdx==%d and subIfIdx==%d"%(iface_t)
	test_ctrl = "not tcp.DstPort==11112"

	if DBG:
		flt_ctrl = '%s and %s'%(iface_ctrl, test_ctrl)
		print(flt_ctrl)
	else:
		flt_ctrl = '%s'%(iface_ctrl)
		pass
	##socket & thread init
	skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	pkt_q = Queue.Queue()
	runHandle = threading.Thread(target=runThread, args=(pkt_q, ))
	runHandle.setDaemon(True)
	runHandle.start()
	updateHandle = threading.Thread(target=updateThread)
	updateHandle.setDaemon(True)
	updateHandle.start()
	pass

if __name__ == '__main__':
	init()
	try:
		printh("CapMain", "Now on %s"%(str(iface_t)), "green")
		main()
	except Exception as e:
		printh("CapMain", e, 'red') #for debug
		w.close()
		pass
