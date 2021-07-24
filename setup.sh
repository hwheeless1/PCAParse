#!/bin/bash

#Creating a Setup Folder wherever you run this script from
#Download the code for our program from GitHub
#Make it executable as well as a command itself

mkdir -p ./Setup
cd Setup
wget -O PCAParse.py https://raw.githubusercontent.com/hwheeless1/PCAParse/main/pcap-parser.py 
chmod +x PCAParse.py
ln -s "$(pwd)"/PCAParse.py /usr/bin/PCAParse

#Download Required Modules for Python Script

apt-get install python3-pip
pip install dpkt
pip install scapy
pip install pyfiglet
echo
echo 'You Have Installed PCAParse and All Required Packages!'
