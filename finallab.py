import scapy.all import

interface = "Ethernet"
address_range = "192.168.1.0/24"
broadcast_addr = "ff:ff:ff:ff:ff:ff"

packet = Ether(dst=broadcast_addr)/ARP(pdst = address_range)

ans, unans = srp(packet, timeout =2, iface=interface, inter=0.1)

for send,receive in ans:
        print (receive.sprintf(r"%Ether.serc% - %ARP.prsc%"))
