#! /usr/bin/python

dhcp_discover=(
	Ether(dst="ff:ff:ff:ff:ff:ff")/
	IP(src="0.0.0.0",dst="255.255.255.255")/
	UDP(sport=68,dport=67)/
	BOOTP(chaddr=hw)/
	DHCP(options=[("message-type","discover"),"end"]
	)
ans,unans=srp(dhcp_discover,multi=True)# Press CTRL-C after several seconds

if __name__ == '__main__':
	main()