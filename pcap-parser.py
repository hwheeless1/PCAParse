#!/usr/bin/env python3  

import sys
import dpkt

counter=0
ipcounter=0
tcpcounter=0
udpcounter=0

filename = sys.argv[1]

for ts, pkt in dpkt.pcap.Reader(open(filename,'rb')):

    counter+=1
    eth=dpkt.ethernet.Ethernet(pkt) 
    if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
       continue

    ip=eth.data
    ipcounter+=1

    if ip.p==dpkt.ip.IP_PROTO_TCP: 
       tcpcounter+=1

    if ip.p==dpkt.ip.IP_PROTO_UDP:
       udpcounter+=1

print ("Total number of packets in the pcap file: ", counter)
print ("Total number of ip packets: ", ipcounter)
print ("Total number of tcp packets: ", tcpcounter)
print ("Total number of udp packets: ", udpcounter)



# Three Phases of the PCAP Parser


# Parsing of the PCAP
#     Making sure it can move through, count packets, count protocols accurately.
#     Save as CSV file
#     Make it user friendly 

# Input Functionality
#     Making sure you can put in IP addresses, protocols, etc to sort through DST/SRC information to track relevant information. 
#     parsing for strings

# Flexibility
#     Can you work through in multiple formulations? Is it smart enough to pull HTTP(doable), JPG files(probably not)? 
#     Not worried about GUI. Maybe just tell you where in the packets jpgs could be.