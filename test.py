
import ifaddr

adapters = ifaddr.get_adapters()

for x in adapters:
	tmp_tuple = x.ips[0].ip
	iface_tuple = (tmp_tuple[2], tmp_tuple[1])
	print("%s\t\t\t%r"%(x.nice_name, iface_tuple))
	pass
