#! /usr/bin/python
'''
Sniff and UDP.py
@author: Mark Hong
@level: debug
'''
import socket, time, Queue, threading
from TxRegisterDaemon import TxRegisterDaemon
from Utility import *
import pydivert

global w, iface_t, subnet_map
DBG = 1

def packet_wrapper(packet):
	global subnet_map
	ipAddr = packet.dst_addr
	ipAddr_raw = ip2int(ipAddr)
	fraw = str(bytearray(packet.raw))
	fid = ''

	tmp = subnet_map #atom
	for k,v in tmp.items():
		if ipAddr in v['subnet']:
			fid = k
			break
		pass

	if fid:
		packet = struct_helper((ipAddr_raw, fid), fraw)
		if DBG: packet = fraw
		return packet
	else:
		return ''

def runThread(pkt_q):
	global count, length
	while True:
		if not pkt_q.empty():
			p = pkt_q.get()
			if DBG: print(p.src_addr, p.dst_addr, p.interface)
			udp_packet = packet_wrapper(p) #for future use
			if udp_packet:
				skt.sendto(udp_packet, ('localhost', 12345))

				count += 1
				length += len(udp_packet)
				remains = pkt_q.qsize()
				print("%d\t%d\t%.2f MB"%(count, remains, length/1E6))
				pass
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
	subnet_map = {}

	##init parameter from json
	config = load_json('./config.json')
	udp_port = config['udp_port']
	iface_t = get_iface(config['cap_iface'])
	ipAddr = get_ipAddr(config['cap_iface'])
	struct_helper = StructHelper(config["frame"]) #'IB'=IPAddr+RxID

	flt_ctrl = "inbound and ifIdx==%d and not ip.DstAddr==%s"%(iface_t[0], ipAddr)
	if DBG: print(flt_ctrl)

	##socket & thread init
	skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	pkt_q = Queue.Queue()
	runHandle = threading.Thread(target=runThread, args=(pkt_q, ))
	updateHandle = TxRegisterDaemon(subnet_map)
	exec_watch(runHandle, fatal=True, hook=tx_exit)
	exec_watch(updateHandle, fatal=False)
	pass

def tx_exit():
	w.close()
	pass

if __name__ == '__main__':
	init()
	try:
		printh("CapMain", "Now on %s"%(str(iface_t)), "green")
		main()
	except Exception as e:
		printh("CapMain", e, 'red') #for debug
		pass
