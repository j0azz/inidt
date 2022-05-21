from scapy.all import *
import os, sys


class sniffer():
    def __init__(self, n_of_packets=10):
        self.start(n_of_packets)
    
    def start(self, n):
        sniff(prn=lambda pkt: self.store(pkt), count=n)
    
    def store(self, pkt):
        raw_pcap = open("raw.pcap", "w")
        raw_pcap.write(str(raw(pkt)))
        raw_pcap.close()

        print(pkt.summary())
        print("\n\n\n")
        hexdump(pkt)
        print("\n\n\n")
        pkt.show()
        print("\n\n\n")
        ls(pkt)
sniff(iface="ath0", prn=lambda x:x.sprintf("{Dot11Beacon:%Dot11.addr3%\t%Dot11Beacon.info%\t%PrismHeader.channel%\t%Dot11Beacon.cap%}"))
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


