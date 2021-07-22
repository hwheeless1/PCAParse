#!/usr/bin/env python3  

# import sys
import dpkt
import os
from pyfiglet import Figlet


# Inputs:
# Need to start cleaning up and calling to specific built-in functions
# Keep it clean(no reusing variables)
# Start building out text for user functionality
# Print out the enviroment

def banner_message():
    f = Figlet(font='slant')
    print (f.renderText("PCAParser"))

def live_capture():
    os.system("tshark -D")

    cap_int = str(input("Which interface are you looking to scan?"))
    out_file = str(input("Where do you want this file saved?"))
    # packet_check = str(input("Do you want a limit on packet amount?[y/n]"))
    # if packet_check == "y" or "yes" or "Y" or "Yes":
    packet_count = int(input("How many packets do you want counted?"))
    # else:
    #    pass  
    os.system("tshark -T fields -e frame.time -i {} -w {}.pcap > {} -F pcap -c {}".format(cap_int, out_file, out_file, packet_count))

def convert():
    filename = input("Enter your filename:")
    x = str(input("Enter your destination file here:"))
    os.system ('tshark -r'+filename +'>'+ x +'.txt')

def counters():
    counter=0
    ipcounter=0
    tcpcounter=0
    udpcounter=0
    filename = input("Enter your filename:")
    if filename[-2:] == "ng":
        x = dpkt.pcapng.Reader(open(filename, 'rb'))
    else:
        x = dpkt.pcap.Reader(open(filename, 'rb'))

    for ts, pkt in x:

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
    print ("Beginning PCAP Parser")
    print ("Total number of packets in the pcap file: ", counter)   
    print ("Total number of ip packets: ", ipcounter)
    print ("Total number of tcp packets: ", tcpcounter)
    print ("Total number of udp packets: ", udpcounter)

def export():
    filename = input("Enter your filename: ")
    dst = input("Enter destination file :")
    print("What file type are you looking for? Enter only 1\n dicom \n http \n imf \n smb \n tftp")
    export = input("Enter export object type: ")
    os.system("tshark -r  {} --export-objects {}, {}" .format  (filename, export, dst))

def main():
    if 'a' == 'a':
        print("Hello")

if __name__ == '__main__':      
    main()        
