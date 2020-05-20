#! /usr/bin/env python3

# iptables -t nat -A PREROUTING -p tcp --dport 22 -j NFQUEUE --queue-num 1
from scapy.all import *
from netfilterqueue import NetfilterQueue
#conf.L3socket=L3RawSocket
import socket
import re

def check_pkt(packet):
    pkt = IP(packet.get_payload())
#    print(pkt)
    #packet.set_payload(str(pkt)) #set the packet content to our modified version
#    packet.accept() #accept the packet

#    if packet[0][1].dst == '140.82.118.4':
#        address = socket.gethostbyaddr(packet[0][1].dst) 
#        print(address)
    host, alias, ip = socket.gethostbyaddr(pkt[IP].dst)
    github = re.search("github.com", host)
    if github is not None:
        print(host)
#        print(pkt[TCP].dport)
#        pkt[TCP].dport = 6660
#        print(pkt[TCP].dport)
        packet.accept() #accept the packet
    else:
        pkt[IP].dst = '172.17.0.3'
        print(pkt.dst)
        pkt[TCP].dport = 6660
#        #packet = IP()/TCP(dport=6660)/"Blocked mouhahaha"
#        #send(packet/TCP(dport=6660))
#        #sendp(packet)
#        #sendp(TCP(dport=6660) / IP(dst="172.17.0.3"))
#        #print(packet[0][1].dest)
        packet.set_payload(bytes(pkt)) #set the packet content to our modified version
        packet.accept() #accept the packet

#sniff(filter="src host 172.29.8.21 and dst port 22", prn=check_pkt)

nfqueue = NetfilterQueue()
#1 is the iptabels rule queue number, modify is the callback function
nfqueue.bind(1, check_pkt) 
try:
    print("[*] waiting for data")
    nfqueue.run()
except KeyboardInterrupt:
    pass

