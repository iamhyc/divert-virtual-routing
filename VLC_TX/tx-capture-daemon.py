#! /usr/bin/python
'''
Tx Capture Daemon.py
@author: Mark Hong
@level: debug
'''
import socket, time, Queue, threading
from TxRegisterDaemon import TxRegisterDaemon
from Utility import *
import pydivert

global w, iface_t
DBG = 0

def packet_wrapper(packet):
	global proxy_map
	ipAddr = packet.dst_addr
	ipAddr_raw = ip2int(ipAddr)
	fraw = str(bytearray(packet.raw))
	fid = ''

	tmp = proxy_map #atom
	for k,v in tmp.items():
		if ipAddr in v:
			fid = k
			break
		pass

	if fid:
		#packet = struct_helper((ipAddr_raw, fid), fraw)
		#packet = "%d %s %s"%(ipAddr_raw, fid, fraw)
		packet = fraw
		return packet
	else:
		return ''

def runThread(pkt_q):
	global w
	count, length = 0, 0
	while True:
		if not pkt_q.empty():
			p = pkt_q.get()
			udp_packet = packet_wrapper(p) #for future use
			if udp_packet:
				if DBG: skt.sendto(udp_packet, ('192.168.1.127', udp_port))
				skt.sendto(udp_packet, ('localhost', udp_port))

				count += 1
				length += len(udp_packet)
				remains = pkt_q.qsize()
				print("%d\t%d\t%.2f MB"%(count, remains, length/1E6))
				pass
			else:
				w.send(p) #send back others
				pass
			pass
		pass
	pass

def main():
	global flt_ctrl, w
	w = pydivert.WinDivert(flt_ctrl)
	w.open()
	while True:
		packet = w.recv()
		pkt_q.put(packet)
		pass
	pass

def init():
	global struct_helper
	global skt, pkt_q, flt_ctrl, iface_t, udp_port, proxy_map
	proxy_map = {} #default empty proxy

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
	updateHandle = TxRegisterDaemon(proxy_map)
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
