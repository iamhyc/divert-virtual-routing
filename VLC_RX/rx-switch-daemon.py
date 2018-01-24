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

global w_ul, w_dl
DBG = 0

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

def runBlockThread():
	global proxy_map, w_block
	block_flt = "outbound and ifIdx==%s and not ip.DstAddr==%s"%(iface_back, config['reg_server'])
	##"outbound and ifIdx==22 and not ip.SrcAddr==192.168.1.220 and not ip.DstAddr==192.168.1.2"
	w_block = pydivert.WinDivert(block_flt, priority=-1000)
	w_block.open()
	while True:
		p = w_block.recv()
		if p.src_addr in proxy_map.values():#modified packet
			w_block.send(p)
		else:
			pass#block out
		pass
	pass

def runProxyThreadUL():
	global w_ul, config, exFilter, iface_back
	
	sniff_flt = "ip and not ip.SrcAddr==127.0.0.1"
	w_ul = pydivert.WinDivert(sniff_flt, priority=-900,
		layer=pydivert.Layer(1))
	w_ul.open()
	printh("UL-Thread", "Now on %s"%(str(iface_back)), "green")

	while True:
		p = w_ul.recv()
		tmp = proxy_func(p.src_addr, 0)
		if tmp:
			p.src_addr = tmp
			# p.interface = iface_back
			# p.direction = pydivert.Direction(0) #0 for OUT_BOUND
			w_ul.send(p, recalculate_checksum=True)
			pass
		pass
	pass

def runProxyThreadDL(data_q):
	global iface_back, w_dl
	w_dl = pydivert.WinDivert('false', layer=pydivert.Layer(1))
	w_dl.open()
	printh("DL-Thread", "Now on %s"%(str(iface_back)), "green")

	count, length = 0, 0
	while True:
		if not data_q.empty():
			data = data_q.get()
			v = memoryview(bytearray(data))
			p = pydivert.Packet(v, (17L,0L),
					pydivert.Direction(0) #0 for OUT_BOUND
					)
			tmp = proxy_func(p.dst_addr, 1)
			if tmp:
				p.dst_addr = tmp
				try:
					w_dl.send(p, recalculate_checksum=True)
				except Exception as e:
					printh("Debug", e, 'red')
					pass

				length += len(data)
				count += 1
				remains = data_q.qsize()
				if DBG: print("%d\t%d\t%.2f MB"%(count, remains, length/1E6))
				pass
			else:
				if DBG: print('correspondance loss.')
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
	global proxyHandleUL, proxyHandleDL
	proxy_map = {} #default empty proxy

	config = load_json('./config.json')
	iface_back = get_iface(config['iface_back'])
	iface_front = get_iface(config['iface_front'])
	exFilter = config['exFilter']

	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind(('', config['udp_port']))
	sock.setblocking(False)

	data_q = Queue.Queue()
	runBlockHandle = threading.Thread(target=runBlockThread)
	proxyHandleUL = threading.Thread(target=runProxyThreadUL)
	proxyHandleDL = threading.Thread(target=runProxyThreadDL, args=(data_q, ))
	updateHandle = RxRegisterDaemon(proxy_map)
	exec_watch(runBlockHandle, fatal=False)
	exec_watch(proxyHandleUL, fatal=True, hook=rx_exit)
	exec_watch(proxyHandleDL, fatal=True, hook=rx_exit)
	exec_watch(updateHandle, fatal=False)
	pass

def rx_exit():
	join_helper((proxyHandleUL, proxyHandleDL))
	w_block.close()
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