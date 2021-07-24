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

def banner_message(message):
    if message == "start":
        f = Figlet(font='slant')
        return (f.renderText("PCAParser"))

def live_capture(param):
    return(os.system("tshark -T fields -e frame.time -i {} -w {}.pcap > {} -F pcap -c {}".format(*param)))

def convert(param2):
    os.system ('tshark -r {} > {}.txt'.format(*param2))

def counters(filename):
    counter=0
    ipcounter=0
    tcpcounter=0
    udpcounter=0
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
    print ("Rough amount of data in your current PCAP:")
    print ("Total number of packets in the pcap file: ", counter)   
    print ("Total number of ip packets: ", ipcounter)
    print ("Total number of tcp packets: ", tcpcounter)
    print ("Total number of udp packets: ", udpcounter)

def export(param4):
        os.system("tshark -r  {} --export-objects {}, {}" .format  (*param4))

def input_check(usr_prompt, error, is_valid, valid_list):
    user_input = input(usr_prompt)
    while not is_valid(user_input, valid_list):
        print(error)
        user_input = input(usr_prompt)
    return user_input

# input_check helper function.
def validate_list(item, lst):
    if item not in lst:
        return False
    return True
 
# input_check helper function.
def validate_number(item, lst):
    if item.isdigit() and int(item) <= len(lst):
        return True
    return False
 
def main():
    print(banner_message("start"))
    # print(WELCOME MESSAGE)
    print("Are you working on a live capture or existing PCAP?")
    choice = input_check("Type L for live Capture OR E for Existing PCAP   ", "Invalid input. Expected L or M." , validate_list, ["E", "e", "L", "l"])
    if choice in ["L", "l"]:
        os.system("tshark -D")
        cap_int = str(input("Which interface are you looking to scan?"))
        out_file1 = str(input("Where do you want this file saved?"))
        out_file2 = "/tmp/"+out_file1
        print("Your file will be saved as " + out_file2 + " and as "+out_file2+".pcap")
        packet_count = int(input("How many packets do you want counted?"))
        param = cap_int, out_file2, out_file2, packet_count
        print(live_capture(param))
    
    elif choice in ["E", "e"]:
        os.system("ls -hl *pcap*")
        filename = input("Enter your filename: ")
        print(counters(filename))
        print("Are you looking to convert this PCAP to a CSV?")
        choice2 = input_check("Y or N?   ", "Invalid input, Expected Y or N." , validate_list, ["yes", "Yes", "Y", "y", "No", "no", "n", "N"])
        if choice2 in ["yes", "Yes", "Y", "y"]:
            dst_file = str(input("Enter your destination file here:"))
            dst_file2 = "/tmp/" + dst_file
            print("Your file will be saved as" + dst_file2)
            param2 = filename, dst_file2
            print(convert(param2))
        elif choice2 in ["No", "no", "n", "N"]:
            print("So are we looking to Export[X] or Search[S] within the PCAP?")
            choice3 = input_check("S or X  ", "Invalid input, Expected S or X." , validate_list ["S", "s", "X", "x"])
            if choice3 in ["x", "X"]:
                dst_file = str(input("Enter your destination file here:"))
                dst_file2 = "/tmp/"+dst_file
                print("Your file will be saved as" + dst_file2)
                print("What file type are you looking for? Enter only 1:\n dicom \n http \n imf \n smb \n tftp")
                export = input("Enter export object type: ")
                param4 = filename, export, dst_file2
                print(export(param4))
            # elif choice3 in 

    

if __name__ == '__main__':      
    main()        
