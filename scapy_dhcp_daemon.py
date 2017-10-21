#! /usr/bin/python

from scapy.all import *
from time import ctime,sleep
import json, socket, threading

######################################
# Necessary Network functions not included in scapy
#
def randomMAC():
	mac = [ 0x00, 0x0c, 0x29,
	random.randint(0x00, 0x7f),
	random.randint(0x00, 0xff),
	random.randint(0x00, 0xff) ]
	return ':'.join(map(lambda x: "%02x" % x, mac))

class DHCP_Proxy(threading.Thread):
	"""Non-Blocking running DHCP_Proxy Thread
		@desc 
		@param (int)state:
			0: Ready; 4: ACK_rx && Maintain State;
			1: Discover_tx; 2:Offer_rx; 3:Request_tx;
		@param (dict)param
			store the {ip, mac, mask, gateway, ttl}
			information
		@func request:
			perform the four-phase procedure for DHCP
			proxy request
		@func release:
			(not implemented yet)
		@func 
	"""
	def __init__(self, task_id):
		threading.Thread.__init__(self)
		self.id = task_id
		self.state = 0#ready state

	def run(self):
		#time.sleep(20)
	
	def request():
		pass

	def release():
		pass


def main():
	thread_map = {}
	skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	skt.bind(('localhost', 11112))

	while True:
		print('Waiting for frontend call...')
    	data, addr = skt.recvfrom(1024)

    	try:
    		cmd, task_id = data.split(';');
    		if not thread_map.has_key(task_id):
    			if cmd=='connect':
    				thread_map[task_id] = DHCP_Proxy(task_id)
    				pass
    		else:
    			if cmd=='stop':
    				thread_map[task_id].stop()
    				del thread_map[task_id]
    				pass
    			elif cmd=='release':
    				thread_map[task_id].release()
    				del thread_map[task_id]
    				pass
    		pass
    	except Exception as e:
    		print("Socket Error... >> " + data)
    		raise e

if __name__ == '__main__':
	global skt, thread_map
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