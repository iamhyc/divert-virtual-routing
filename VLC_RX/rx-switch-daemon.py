#! /usr/bin/python
'''
(Rx) Switch Daemon.py
@author: Mark Hong
@level: debug
'''
import socket, threading, Queue
from Utility import *
from RxRegisterDaemon import RxRegisterDaemon
import pydivert, ifaddr

global w_block, w_sniff, w_ul, w_dl
DBG = 1

def proxy_func(addr, reverse=0):
	global proxy_map
	tmp = proxy_map #atom
	try:
		if reverse:
			remap = tmp.keys()[tmp.values().index(addr)]
			return str(remap)
		else:
			remap = tmp.values()[tmp.keys().index(addr)]
			return str(remap)
	except Exception as e:
		return ""
	pass

def runProxyThreadUL():
	global w_ul, w_sniff, config, exFilter, iface_back
	
	sniff_flt = "not ip.DstAddr==%s and not %s"%(config["reg_server"], exFilter)
	w_sniff = pydivert.WinDivert(sniff_flt, priority=-1000,
		layer=pydivert.Layer(1))
	w_sniff.open()
	w_ul = pydivert.WinDivert("false")
	w_ul.open()
	printh("UL-Thread", "Now on %s"%(str(iface_back)), "green")

	while True:
		p = w_sniff.recv()
		tmp = proxy_func(p.src_addr, 0)
		if tmp:
			p.src_addr = tmp
			p.interface = iface_back
			p.direction = pydivert.Direction(0) #0 for OUT_BOUND
			w_ul.send(p, recalculate_checksum=True)
			if DBG: print(p.src_addr, p.dst_addr) #for debug
			pass
		pass
	pass

def runProxyThreadDL(data_q):
	global count, length, iface_back, w_dl
	w_dl = pydivert.WinDivert('false')
	w_dl.open()
	printh("DL-Thread", "Now on %s"%(str(iface_back)), "green")

	while True:
		if not data_q.empty():
			data = data_q.get()
			v = memoryview(bytearray(data))
			p = pydivert.Packet(v, iface_back,
					pydivert.Direction(1) #1 for IN_BOUND
					)
			tmp = proxy_func(p.dst_addr, 1)
			if tmp:
				p.dst_addr = tmp
				w_dl.send(p, recalculate_checksum=True)
				length += len(data)
				count += 1
				remains = data_q.qsize()
				print("%d\t%d\t%.2f MB"%(count, remains, length/1E6))
				pass
			else:
				print('correspondance loss.')
				pass
			pass
		pass
	pass

def sock_main():
	global sock, data_q
	while True:
		try:
			data, addr = sock.recvfrom(4096)
			data_q.put(data)
		except Exception as e:
			pass#try(sock)
		pass#while
	pass

def init():
	global config, proxy_map, sock, data_q, iface_back, iface_front, exFilter
	global blockHandle, proxyHandleUL, proxyHandleDL
	proxy_map = {} #default empty proxy

	config = load_json('./config.json')
	iface_back = get_iface(config['iface_back'])
	iface_front = get_iface(config['iface_front'])
	exFilter = config['exFilter']

	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind(('', config['udp_port']))
	sock.setblocking(False)

	data_q = Queue.Queue()
	proxyHandleUL = threading.Thread(target=runProxyThreadUL)
	proxyHandleDL = threading.Thread(target=runProxyThreadDL, args=(data_q, ))
	updateHandle = RxRegisterDaemon(proxy_map)
	exec_watch(proxyHandleUL, fatal=True, hook=rx_exit)
	exec_watch(proxyHandleDL, fatal=True, hook=rx_exit)
	exec_watch(updateHandle, fatal=False)
	pass

def rx_exit():
	join_helper((blockHandle, proxyHandleUL, proxyHandleDL))
	w_sniff.close()
	w_ul.close()
	w_dl.close()
	pass

if __name__ == '__main__':
	init()
	try:
		sock_main()
	except Exception as e:
		printh("RxDaemon", e, 'red')
	finally:
		rx_exit()