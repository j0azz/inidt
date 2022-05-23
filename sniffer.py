
#!/usr/bin/python3

from scapy.all import *
import sys, time

class sniffer():
    def __init__(self, n_of_packets=10, interface=None):
        self.start(n_of_packets, interface)
    
    
    def start(self, n, interface):
        captured = sniff(iface=interface, prn=lambda pkt: self.store(pkt), count=n)
        wrpcap("captured.pcap", captured)
    
    def store(self, pkt):
        print("\n\n\n\n[+]=== PACKET CAPTURED ===[+]")
        print(pkt.summary())
        print("\n\n\n")
        hexdump(pkt)
        print("\n\n\n")
        pkt.show()
        print("\n\n\n")
        ls(pkt)

if(len(sys.argv)>=2):
    n = int(sys.argv[1])
    if(type(n)==int):
        sniffer(n)
    else:
        print("usage: \npython3 sniffer.py <num_of_packets>\n")
else:
    print("usage: \npython3 sniffer.py <num_of_packets>\n")
    print("capturing 10 packets...\n\n")
    sniffer()


