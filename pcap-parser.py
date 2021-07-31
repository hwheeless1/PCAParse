#!/usr/bin/env python3  

# import sys
import dpkt
import os
from pyfiglet import Figlet
import time

def banner_message(message):
    if message == "start":
        f = Figlet(font='slant')
        return(f.renderText("PCAParser"))

def live_capture(param):
    option = input_check("Did you want to scan the live capture for anything specific? If so, please refer to our Github for DISPLAY FILTER SYNTAX. Type Y or N     " , "Invalid input: Expected Y or N" , validate_list, ["Y", "y", "N", "N"])
    if option in ["Y", "y"]:
        search = input("What display filter option(s):    ")
        param_list = list(param)
        param_list.append(search)
        new_param = tuple(param_list)
        print(new_param)
        return(os.system("tshark -i {} -w {}.pcapng {} -f {} ".format(*new_param)))
    else:
        return(os.system("tshark -i {} -w {}.pcapng {} ".format(*param)))

    
def convert(param2):
    return(os.system ('tshark -r {} -T fields -E header=y -E separator=, -E quote=d -E occurrence=f -e ip.version -e ip.hdr_len -e ip.tos -e ip.id -e ip.flags -e ip.flags.rb -e ip.flags.df -e ip.flags.mf -e ip.frag_offset -e ip.ttl -e ip.proto -e ip.checksum -e ip.src -e ip.dst -e ip.len -e ip.dsfield -e tcp.srcport -e tcp.dstport -e tcp.seq -e tcp.ack -e tcp.len -e tcp.hdr_len -e tcp.flags -e tcp.flags.fin -e tcp.flags.syn -e tcp.flags.reset -e tcp.flags.push -e tcp.flags.ack -e tcp.flags.urg -e tcp.flags.cwr -e tcp.window_size -e tcp.checksum -e tcp.urgent_pointer -e tcp.options.mss_val > {}.txt'.format(*param2)))

def seeker(filename):
    print("So, this is a bit advanced, so we don't have all 100 or so Display\
Filters ready to pull in, so we have slimmed down the options as follows:\
\nip.<addr/dst/src> (for searching for a specific IP Address)\nipv6.\
<addr/dst/src> (ipv6 IP Address)\n<udp/tcp>.<port/dst/src> (Searching for TCP/UPD port numbers\n\
So if you want a better break down of how to use Search Filter options, please refer to our additional documentation\
available on our github.")
    search = str(input("With that out of the way, please enter your desired Display Filter search:"))
    destination = "/tmp/" + str(input("We are going to put this into your tmp folder, please enter file name:")) + ".pcapng"
    return(os.system('tshark -r {} -Y "{}" -w {}'.format(filename, search, destination)))


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
    return ("Rough amount of data in your current PCAP:\n\
             Total number of packets in the pcap file: {}\n\
             Total number of ip packets: {}\n\
             Total number of tcp packets: {}\n\
             Total number of udp packets: {}").format(counter,ipcounter,tcpcounter,udpcounter)

def export(param4):
        return(os.system("tshark -r {} --export-objects {},{}".format(*param4)))

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
    print("Welcome to PCAParse, your handy dandy swiss army knife to help you easily parse PCAP files.")
    print("Are you working on a live capture or existing PCAP?")
    choice = input_check("Type L for live Capture OR E for Existing PCAP   ", "Invalid input. Expected L or M." , validate_list, ["E", "e", "L", "l"])
    if choice in ["L", "l"]:
        print("Live Capture Needs to ran as sudo/root user")
        time.sleep(2)
        os.system("tshark -D")
        cap_int = str(input("Which interface are you looking to scan? (name or number)"    ))
        out_file = "/tmp/" + str(input("Where do you want this file saved?"    ))
        print("Your file will be saved as " + out_file)
        print("Are you looking to save a particular number of packets or a timed capture?")
        choices = input_check("Type c for Count or a for Time:   ", "Invalid input. Expected c or a." , validate_list, ["a", "A", "c", "C"])
        if choices in ["a", "A"]:
                option = int(input("How long do you want to scan for (in seconds):     "))
                packet_count ="-a duration:%d" % (option,)
        else:
                packet_count = "-c " + (input("How many packets do you want captured:      "))
        param = cap_int, out_file, packet_count
        print(type(param))
        print(live_capture(param))
    
    elif choice in ["E", "e"]:
        os.system("ls -hl *pcap*")
        filename = input("Enter your filename:    ")
        print(counters(filename))
        print("Are you looking to convert this PCAP to a CSV?")
        choice2 = input_check("Y or N?   ", "Invalid input, Expected Y or N." , validate_list, ["yes", "Yes", "Y", "y", "No", "no", "n", "N"])
        if choice2 in ["yes", "Yes", "Y", "y"]:
            dst_file = "/tmp/" + str(input("Enter your destination file here:   "))
            print("Your file will be saved as" + dst_file)
            param2 = filename, dst_file
            print(convert(param2))
        elif choice2 in ["No", "no", "n", "N"]:
            print("So are we looking to Export[X] or Search[S] within the PCAP?")
            choice3 = input_check("S or X?    ", "Invalid input, Expected S or X." , validate_list, ["S", "s", "X", "x"])
            if choice3 in ["x", "X"]:
                dst_dir = "/tmp/" +str(input("Enter your destination directory:     "))
                print("Your directory will be saved as" + dst_dir)
                print("What file type are you looking for? Enter only 1:\n dicom \n http \n imf \n smb \n tftp")
                exports = str(input("Enter export object type:     "))
                param4 = filename, exports, dst_dir
                print(export(param4))
                print("You can find your destination folder here:   {}".format(dst_dir))
            elif choice3 in ["S", "s"]:
                print(seeker(filename))    

if __name__ == '__main__':      
    main()        
