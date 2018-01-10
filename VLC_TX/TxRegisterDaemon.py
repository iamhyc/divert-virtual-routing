#! /usr/bin/python
'''
Client Register Daemon.py
@author: Mark Hong
@level: debug
'''
import socket, threading
from Utility import ip2int, int2ip, load_json

DBG = 1

class TxRegisterDaemon(threading.Thread):
	"""docstring for TxRegisterDaemon"""
	def __init__(self, subnet_map):
		threading.Thread.__init__(self)
		self.subnet_map = subnet_map
		config = load_json('./config.json')
		self.port_tx = config['reg_port_tx']
		self.port_rx = config['reg_port_rx']
		self.op_map = {
			'request':self.allocation,
			'release':self.release
		}
		## Allocated IP Range
		ip_range = config['ip_range']
		ipA, ipB = [ip2int(x) for x in ip_range]
		self.ip_map = dict(zip( range(ipA, ipB), [0]*(ipB-ipA) ))
		self.class_init()
		pass

	def class_init(self):
		self.sock_rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sock_tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sock_tx.bind(('', self.port_tx))
		self.sock_tx.setblocking(True)
		pass

	def allocation(self, fid):
		if not self.subnet_map.has_key(fid):
			self.subnet_map[fid] = dict({'subnet':[]})
		mapIPIdx = self.ip_map.values().index(0) #find unused IP
		mapIPAddr = self.ip_map.keys()[mapIPIdx]
		self.ip_map[mapIPAddr] = 1 #occupied
		mapIPAddr = int2ip(mapIPAddr)
		self.subnet_map[fid]['subnet'].append(mapIPAddr) #occupied
		return '0 %s'%(mapIPAddr)

	def release(self, ipAddr):
		for k,v in self.subnet_map.items():
			if ipAddr in v['subnet']:
				self.ip_map[ipAddr] = 0
				self.subnet_map[k]['subnet'].pop(ipAddr)
				return '0 %s'%(ipAddr)
			pass
		raise Exception('hehe') #exception		
		pass

	def run(self):
		while True:
			try:
				req, addr = self.sock_tx.recvfrom(1024)
				op, data = req.split(' ')
				res = self.op_map[op](data)
				if not res: raise Exception('hehe')
				self.sock_rx.sendto(res, (addr[0], self.port_rx))
			except Exception as e:
				res = '-1 %s'%(e)
				self.sock_rx.sendto(res, (addr[0], self.port_rx))
			finally:
				if DBG: print(res)
			pass
		pass
