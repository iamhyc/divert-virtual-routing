#! /usr/bin/python

import socket

udp_setup = ('localhost', 11112)

def main():
	skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	skt.bind(udp_setup)

	while True:
		print("Waiting for a new command:")
		data, addr = skt.recvfrom(1024)
		print('Received:',data,'from',addr)
		pass

	pass

if __name__ == '__main__':
	main()

null_ip = "0.0.0.0"
bc_ip = "255.255.255.255"
bc_mac = "ff:ff:ff:ff:ff:ff"
bootp_xid = random.randint(0, sys.maxint)

'''
DHCP Discover Packet
'''
l2 = Ether(dst=bc_mac, src=proxy_mac, type=0x0800)
l3 = IP(src=null_ip, dst=bc_ip)
udp =  UDP(dport=67, sport=68)
bootp = BOOTP(op=1, xid=bootp_xid)
dhcp = DHCP(options=[('message-type','discover'), 
					 ('end')])
packet = l2/l3/udp/bootp/dhcp

'''
DHCP Offer Packet
'''
if req.haslayer(BOOTP):
	bootp = req.getlayer(BOOTP)
	if bootp.xid == self.__xid:
		if req.haslayer(DHCP) and self.__ip is None:
			print "Dhcp packet!"
			dhcp = req.getlayer(DHCP)
			if dhcp.options[0][0] == 'message-type':
				message_type = dhcp.options[0][1]
				# Only interested in offers
				if message_type == 2:
					return 1

'''
DHCP Request Packet
'''
l3 = Ether(dst=req.getlayer(Ether).src, src=self.__mac)
l2 = IP(src=self.__ip, dst=req.getlayer(IP).src)
udp = UDP(sport=req.dport, dport=req.sport)
bootp = BOOTP(op=1, chaddr=self.__mac, xid=self.__xid)
dhcp = DHCP(options=[('message-type','request'),
					 ('client_id', self.__mac),
					 ('requested_addr', self.__ip),
					 ('server_id', self.__router),
					 ('end')])
rep=l3/l2/udp/bootp/dhcp