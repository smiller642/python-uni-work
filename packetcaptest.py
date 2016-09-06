# Packet sniffer in python for Linux
# Only captures incoming TCP packets

import socket
import sys
from struct import *

# create an INET, STREAMing socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error:
    print('Socket could not be created.')
    sys.exit()
x = 0
# receive a packet
while x < 5:
    packet = s.recvfrom(65565)
    # transfer tuple contents to string type
    packet = packet[0]
    # take first 20 characters for the ip header
    ip_header = packet[0:20]
    # now unpack them into usable info
    iph = unpack('!BBHHHBBH4s4s', ip_header)
    #print("iph: " + str(iph))

    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])
    tcp_header = packet[iph_length:iph_length+20]
    #print("packed tcp header: " + str(tcp_header))
    # now unpack them into usable info
    tcph = unpack('!HHLLBBHHH', tcp_header)
    print("tcp header: " + str(tcph))
    x += 0.5
"""
    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcpFlag = tcph[5]
    tcph_length = doff_reserved >> 4
    h_size = iph_length + tcph_length * 4
    data_size = len(packet) - h_size
    # get data from the packet
    data = packet[h_size:]
    # print('Data : ' + str(data))
    if source_port == 80 or source_port == 443:
        if source_port == 80:
        else:
    print("Packet Captured")
"""