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

'''
dhcp_discover=(
	Ether(dst="ff:ff:ff:ff:ff:ff")/
	IP(src="0.0.0.0",dst="255.255.255.255")/
	UDP(sport=68,dport=67)/
	BOOTP(chaddr=hw)/
	DHCP(options=[("message-type","discover"),"end"]
	)
ans,unans=srp(dhcp_discover,multi=True)# Press CTRL-C after several seconds
'''