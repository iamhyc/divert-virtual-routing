#! /usr/bin/python
'''
Client Register Daemon@Rx.py
@author: Mark Hong
@level: debug
'''
import socket, threading
from Utility import load_json, get_ipAddr

class RxRegisterDaemon(threading.Thread):
	"""docstring for RxRegisterClass"""
	def __init__(self, proxy_map):
		threading.Thread.__init__(self)
		config = load_json('./config.json')
		self.proxy_map = proxy_map
		self.reg_id = config['reg_id']
		self.iface = config['iface_back']
		self.server_t = (config['reg_server'], config['reg_port_tx'])
		self.reg_port_rx = config['reg_port_rx']
		self.class_init()
		pass

	def class_init(self):
		self.sock_tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sock_rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sock_rx.bind(('', self.reg_port_rx))
		self.sock_rx.settimeout(1.0)
		pass

	def request(self):
		cmd = "%s %s"%('request', self.reg_id)
		self.sock_tx.sendto(cmd, self.server_t)
		res, addr = self.sock_rx.recvfrom(1024)
		if res: return res
		return ""

	def release(self, ipAddr):
		cmd = "%s %s"%('release', ipAddr)
		self.sock_tx.sendto(cmd, self.server_t)
		res, addr = self.sock_rx.recvfrom(1024)
		if res: return res
		pass

	def run(self):
		while True:
			ipAddr = "192.168.137.44"#get_ipAddr(self.iface)
			if not (ipAddr in self.proxy_map.keys()):
				status, mapIPAddr = self.request().split(' ')
				if status=='0':
					self.proxy_map[ipAddr] = mapIPAddr
					pass
				pass
			pass
		pass
