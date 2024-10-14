from scapy.all import ARP, Ether, srp

def scan_network(ip_range):
    arp_request = ARP(pdst=ip_range)
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether_frame / arp_request
    result = srp(packet, timeout=3, verbose=0)[0]
    ip_list = [response[1].prsc for response in result]
    return ip_list

if __name__ =="__main__":
    network = "192.168.1.0/24"
    found_ips = scan_network(network)
    print(f"IP addresses found: {found_ips}")
