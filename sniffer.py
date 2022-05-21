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

sniffer(1)
