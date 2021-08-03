# PCAParse
**PCAP Parsing**

Welcome to our GitHub! The program we have created is called PCAParse if you haven't noticed already.
It was designed to be a multi-faceted tool that helps filter through PCAPs without having to open Wireshark
nor do you need to fumble around with tshark syntax. It does not replace the use of Wireshark or tshark alike,
however it will assist with quick searches/data dumps. This tool was made with security analysts in mind but is
not exclusive to the role, our program will truly work for anybody who needs to review packet captures.

Current Features of the Program include:
Live Capture, Reviewing Existing Captures, Dumping data to CSV, and Search Functionality

______________________________________________________________________________________________________________________

**Getting Set Up**

Please take note of our [Requirements File](https://github.com/hwheeless1/PCAParse/blob/main/Requirements.txt) as well as our [Setup Script](https://github.com/hwheeless1/PCAParse/blob/main/setup.sh), as these will assist you with downloading our 
program on any *Linux System* that you'd like. We recommend using wget to download our setup bash script, but once that
is on your system and executed (**AS SUDO**) you should be ready to go !! The link below can be copied for wget usage.

https://raw.githubusercontent.com/hwheeless1/PCAParse/main/setup.sh 

______________________________________________________________________________________________________________________

**Functionality**

Briefly mentioned before, our program has a few built in capabilities. These include the ability to capture packets in
real time, as well as reviewing any existing packet captures on your system. Our live capture function will let you choose
how much is captured in relation to time elapsed or number of packets captured. The option to capture live or review an
existing capture also come with the ability to search with specific filters or simply scan for all info. Please be aware 
that filters used for Live Captures are *capture* filters, and anything searched through on an existing capture is a *display* filter.
For more help on filters, please see our [Filter Help](https://github.com/hwheeless1/PCAParse/blob/main/Filter%20Help.md) page.

Our program also includes the ability to take any saved packet capture and convert it to a CSV file for different viewing style.
