#! /usr/bin/python
'''
Client Daemon.py
@author: Mark Hong
@level: debug
'''
import socket, Queue, threading
from Utility import *
import pydivert


def main():
	while True:
		packet = w.recv(bufsize=1500)
		packet.src_addr = snd_ip
		packet.interface = iface_t
		w.send(packet, recalculate_checksum=True)
		pass
	pass

def init():
	global w, iface_t, snd_ip
	config = load_json("./config.json")
	flt = "%s and not %s"%("outbound", config["exFilter"])
	#print(flt) #for debug
	w = pydivert.WinDivert(flt)
	w.open()

	iface_t = get_iface(config["iface_pri"])
	snd_ip = get_ipAddr(config["iface_snd"])
	pass

if __name__ == '__main__':
	init()
	try:
		printh("ClientMain", "Now on %r with %s"%(iface_t, snd_ip), "green")
		main()
	except Exception as e:
		printh("ClientMain", e, "red")
		w.close()