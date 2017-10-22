#! /usr/bin/python

from scapy.all import *
from time import ctime,sleep
import multiprocessing
import json, socket

class DHCP_Proxy(multiprocessing.Process):
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


if __name__ == '__main__':
	global skt, thread_map
	main()

