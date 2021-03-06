Depending on where you are at in the code itself, you are either looking for either **DISPLAY** or **CAPTURE** filter syntax. These are not the same. 

We will start with what seems to be the more familiar of the two, DISPLAY FILTERS. We say this because this is the same syntax you would use in the GUI version of Wireshark. 

## Display Filters

[TShark Display Filter Publication](https://tshark.dev/analyze/packet_hunting/packet_hunting/)

[Display Filter Cheat Sheet](https://packetlife.net/media/library/13/Wireshark_Display_Filters.pdf)

[Another Cheat Sheet](https://www.stationx.net/wireshark-cheat-sheet/)


As for CAPTURE FILTERS there seems to be some added complexity. This is primarily due to the logic engines built into each format, but that is for another day. 

## Capture Filters

[Capture Filter Help](https://gitlab.com/wireshark/wireshark/-/wikis/CaptureFilters)

[TShark Capture Filter Manual](http://www.tcpdump.org/manpages/pcap-filter.7.html)


And if you really wanted to know how tshark parses packets using capture filters, here is a lengthy article on the matter. 


https://tshark.dev/packetcraft/arcana/bpf_instructions/

