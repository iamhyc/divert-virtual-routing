#! /usr/bin/python
from scapy.all import *

UDP_BASE_BOOTP_HEADER = 8
BOOTP_BASE_XID_Offset = 4
BOOTP_BASE_XID_Length = 4

null_ip = "0.0.0.0"
bc_ip = "255.255.255.255"
bc_mac = "ff:ff:ff:ff:ff:ff"
proxy_mac = RandMAC("00:28:f8:7c")
bootp_xid = random.randint(0, 900000000)

m = RandMAC("00:28:f8:7c")
myxid = random.randint(1, 900000000)
mymac = get_if_hwaddr(conf.iface)

global result

dhcp_discover = (
	Ether(src=mymac,dst="ff:ff:ff:ff:ff:ff")/ \
	IP(src="0.0.0.0",dst="255.255.255.255")/ \
	UDP(sport=68,dport=67)/ \
	BOOTP(chaddr=[mac2str(m)],xid=myxid,flags=0xFFFFFF)/ \
	DHCP(options=[('message-type','discover'), 
				  ('end')])
)

set_filter = ('udp and udp[%d:%d]=%d'%(12, 4, myxid))
print(set_filter)

sendp(dhcp_discover, iface=conf.iface)
sniff(iface=conf.iface, \
			filter=set_filter, \
			count=1, timeout=5, \
			prn=lambda x:x[DHCP].options[3][1])
'''
pkt[DHCP].options[0][1]#server_id, 192.168.1.1
pkt[DHCP].options[0][2]#lease_time
pkt[DHCP].options[0][3]#subnet_mask
pkt[DHCP].options[0][4]#router
pkt[DHCP].options[0][5]name_server
'''