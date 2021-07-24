#!/bin/bash
mkdir -p ./Setup
cd Setup
wget -O PCAParse.py https://raw.githubusercontent.com/hwheeless1/PCAParse/main/pcap-parser.py 
chmod +x PCAParse.py
scriptdir=`dirname "$BASH_SOURCE"`
ln -s "$(pwd)"/PCAParse.py /usr/bin/PCAParse
apt-get install python3-pip
pip install dpkt
pip install scapy
echo
echo 'You Have Installed PCAParse and All Required Packages!'
