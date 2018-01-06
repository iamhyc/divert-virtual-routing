#! /usr/bin/python
from scapy.all import *
from time import sleep
import multiprocessing
import socket, string, binascii

global udp_rx_setup, udp_tx_setup
global null_ip, bc_ip, bc_mac, lo_mac
global dhcp_bc_header, dhcp_param_tuple
global skt, proc_map, ops_map

UDP_BASE_BOOTP_HEADER = 8
BOOTP_BASE_XID_Offset = 4
BOOTP_BASE_XID_Length = 4

class DHCP_Proxy(multiprocessing.Process):
	"""Non-Blocking running DHCP_Proxy Process
		@desc 
		@param (int)state:
			0: Ready; 1: Discover(tx); 3: Request(tx);
			2: Offer(rx); 4: ACK(rx) && Maintain State;
		@var (dict)param
			store the {ip, mac, mask, gateway}
			information
		@var (dict)state_map
		@func dhcp_init:
			initialize the `param` dict
		@func append2file:
		@func bootp_parse:
		@func dhcp_discover:
		@func dhcp_request:
	"""

	def __init__(self, task_id, skt_lock):
		multiprocessing.Process.__init__(self)
		self.id = task_id
		self.lock = skt_lock
		self.state_map = {
			0 : self.dhcp_init,
			1 : self.dhcp_discover,
			3 : self.dhcp_request
		}
		self.state = 0
		pass

	def dhcp_init(self):
		self.param = {
			'__filled__' : 0,
			'__acked__' : 0,
			'hostname' : ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(8)), 
			'ip' : bc_ip,
			'mac' : RandMAC("00:28:f8:7c"),#allocate a pseudo mac address
			'gateway' : bc_ip,
			'mask' : bc_ip,
			'xid' : random.randint(1, 900000000)
		}
		self.state = 1
		pass

	def append2file(self):
		pass

	def dhcp_ack_parse(self, pkt):
		#self.state = 4
		self.param['__acked__'] = 1;
		pass

	def dhcp_offer_parse(self, pkt):
		#self.state = 2
		self.param['gateway'] = pkt[DHCP].options[1][1]#server_id
		self.param['ip'] = pkt[BOOTP].yiaddr#Offered IP
		self.param["mask"] = pkt[DHCP].options[3][1]#subnet_mask
		#pkt[DHCP].options[2][1]#lease_time
		#pkt[DHCP].options[5][1]#name_server
		self.param['__filled__'] = 1;
		pass

	def dhcp_request(self):
		mac_str = mac2str(self.param["mac"])
		request_pkt = (
			dhcp_bc_header/ \
			BOOTP(chaddr=mac_str, giaddr=null_ip, xid=self.param['xid'], hops=1, flags=0x0000)/ \
        	DHCP(options=[('message-type','request'),
        				  #('client_id', mac_str),
        				  ('server_id', self.param["gateway"]),
        				  ('requested_addr', self.param["ip"]),
        				  ("hostname", self.param["hostname"]),
        				  ("param_req_list", "pad"),
        				  ('end')])
		)
		set_filter = ('udp and udp[%d:%d]=%d'%(12, 4, self.param['xid']))

		sendp(request_pkt, iface=conf.iface)
		sniff(iface=conf.iface, \
			  filter=set_filter, \
			  count=1, timeout=5, \
			  prn=self.dhcp_ack_parse)
		sleep(5)#DELETE THIS!
		pass

	def dhcp_discover(self):
		mac_str = mac2str(self.param["mac"])
		discover_pkt = (
			dhcp_bc_header/ \
			BOOTP(chaddr=[mac_str], giaddr=null_ip, xid=self.param['xid'], hops=1, flags=0x0000)/ \
			DHCP(options=[('message-type','discover'), 
				  		  ('end')])
		)
		set_filter = ('udp and udp[%d:%d]=%d'%(12, 4, self.param['xid']))

		sendp(discover_pkt, iface=conf.iface)
		sniff(iface=conf.iface, \
			  filter=set_filter, \
			  count=1, timeout=5, \
			  prn=self.dhcp_offer_parse)

		if self.param['__filled__']:
			self.state = 3
		else:
			self.state = 1
		pass

	def run(self):
		while True:
			self.state_map[self.state]()
		pass



def request(task_id, skt_lock):
	if proc_map.has_key(task_id):
		raise Exception

	proc_map[task_id] = DHCP_Proxy(task_id, skt_lock)
	proc_map[task_id].daemon = True
	proc_map[task_id].start()
	pass

def release(task_id, skt_lock):
	if not proc_map.has_key(task_id):
		raise Exception

	#proc_map[task_id].join() # wait for itself exit
	proc_map[task_id].terminate() #forcely exit
	del proc_map[task_id] # delete the item
	pass

def main():
	#single command Receive socket setup
	skt_cmd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	skt_cmd.bind(udp_rx_setup)
	#multi-Send socket setup wit Lock
	skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	skt_lock = multiprocessing.Lock();

	while True:
		data, addr = skt_cmd.recvfrom(1024)
		op, task_id = data.split(' ')
		try:
			ops_map[op](task_id, skt_lock)
		except Exception as e:
			print('\nErrorCode: %s'%(e))
			print('\"%s\" from %s'%(data, addr))
			with skt_lock:
				skt.sendto('-1'+' '+task_id, udp_tx_setup)
			pass
		pass
	pass

if __name__ == '__main__':
	print("Network Interface Initializing, please wait...")
	null_ip = get_if_addr(conf.iface)#"0.0.0.0"
	bc_ip = "192.168.1.1" #"255.255.255.255"
	bc_mac = "b0:95:8e:25:88:05"#"ff:ff:ff:ff:ff:ff"
	lo_mac = get_if_hwaddr(conf.iface)
	dhcp_bc_header = (
		Ether(src=lo_mac,dst="ff:ff:ff:ff:ff:ff")/ \
		IP(src=null_ip,dst=bc_ip)/ \
		UDP(sport=68,dport=67)
	)
	dhcp_param_tuple = (
		chr(1), chr(28), chr(2), chr(3), chr(15), chr(6), \
		chr(119), chr(12), chr(44), chr(47), chr(26), \
		chr(121), chr(42)
	)

	udp_tx_setup = ('localhost', 11111)
	udp_rx_setup = ('localhost', 11112)

	proc_map = {}
	ops_map = {
		'0' : release,
		'1' : request
	}

	print("Now Running over %s ..."%( repr(conf.iface) ))
	main()
	pass