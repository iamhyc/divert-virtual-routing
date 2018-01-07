#! /usr/bin/python
'''
Utility: useful general function utilities
@author: Mark Hong
@level: debug
'''
import ctypes, struct, json
import threading, greenlet, ifaddr
from termcolor import colored, cprint

def load_json(uri):
	try:
		with open(uri) as cf:
			return json.load(cf)
	except Exception as e:
		raise e
	pass

def printh(tip, cmd, color=None, split=' '):
	print(
		colored('[%s]%s'%(tip, split), 'magenta')
		+ colored(cmd, color)
		+ ' '
		)
	pass

def get_iface(target):
	adapters = ifaddr.get_adapters()

	for adapter in adapters:
		if target in adapter.nice_name:
			tmp_tuple = adapter.ips[0].ip
			iface_tuple = (tmp_tuple[2], tmp_tuple[1])
			return iface_tuple
		pass
	return (0L, 0L)
	pass

#next rewrite with greenlet, factory and collection
def exec_watch(process, hook=None, fatal=False, gen=True):
	if gen:#external loop
		process.start()
		t = threading.Thread(target=exec_watch, args=(process, hook, fatal, False))
		t.setDaemon(True)
		t.start()
		pass
	else:#internal loop
		while process.is_alive(): pass
		if fatal and hook: hook()
		pass
	pass

def join_helper(t_tuple):
	for t in t_tuple:
		try:
			if t.is_alive(): t.join()
		except Exception as e:
			raise e
		pass
	pass

class StructHelper(object):
	"""docstring for StructHelper"""
	def __init__(self, frame_s):
		super(StructHelper, self).__init__()
		self.frame = struct.Struct(frame_s) #e.g. "IBB"
		self.cbuffer = ctypes.create_string_buffer(self.frame.size)
		pass
	
	def genPacket(self, head_t, raw):
		if not isinstance(head_t, tuple):
			return ""

		self.frame.pack_into(
			self.cbuffer, 0, head_t)
		header = ctypes.string_at(
			ctypes.addressof(self.cbuffer),
			self.frame.size)

		return (header + raw)
		pass
