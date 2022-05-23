from struct import pack
from scapy.all import *

#sniffed_on443 = sniff(filter="port 443", prn=lambda p:p.summary(), iface="wlp0s20f3", count=1000)
sniffed = sniff(prn=lambda p:p.summary(),count=100)

packets = []
#for p in sniffed:
#    ethernet_dst = p.fields["dst"]
#    ethernet_src = p.fields["src"]
#    
#    p.payload

for p in sniffed:
    pkt = {}
    pkt['ethernet'] = p.fields
    pkt['ip'] = p.payload.fields
    pkt['transport'] = p.payload.payload.fields
    
    packets.append(pkt)
