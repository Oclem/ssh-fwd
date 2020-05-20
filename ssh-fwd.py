#! /usr/bin/env python3

# iptables -t nat -A PREROUTING -p tcp --dport 22 -j NFQUEUE --queue-num 1
# sudo iptables -I OUTPUT -s 172.29.8.21 -p tcp --dport 22 -j NFQUEUE --queue-num 1
from scapy.all import *
from netfilterqueue import NetfilterQueue
#conf.L3socket=L3RawSocket
import socket
import re

def check_pkt(packet):
    pkt = IP(packet.get_payload())
    host, alias, ip = socket.gethostbyaddr(pkt[IP].dst)
    github = re.search("github.com", host)
    if github is not None:
        print(host)
        packet.accept() #accept the packet
    else:
        # Sending the connection to see what is happening beyond the horizon of
        # the black hole
        #pkt[IP].dst = '172.17.0.3'
        #print(pkt.dst)
        #pkt[TCP].dport = 6660
        #packet.set_payload(bytes(pkt)) #set the packet content to our modified version
        #packet.accept() #accept the packet
        # Ou alors on fait un vrai truc et on drop xD
        packet.drop()

#sniff(filter="src host 172.29.8.21 and dst port 22", prn=check_pkt)

nfqueue = NetfilterQueue()
nfqueue.bind(1, check_pkt) 
try:
    nfqueue.run()
except KeyboardInterrupt:
    pass

