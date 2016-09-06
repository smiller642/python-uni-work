import socket
import binascii
import struct
import pdb
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

while True:
    #pdb.set_trace()
    packet = s.recvfrom(65565)
    # transfer tuple contents to string type
    packet = packet[0]
    # take first 20 characters for the ip header
    ip_header = packet[0:20]
    # Unpack raw hex bytes into useable format
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    ttl = iph[5]
    protocol = "TCP"
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])
    tcp_header = packet[20:40]
    # Unpack raw hex of tcp_header to get ports and other info
    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
    h_size = iph_length + tcph_length * 4
    data_size = len(packet) - h_size
    tcpFlag = packet[33:34].hex()
        
    if tcpFlag == "01":
        Flag = "FIN"
    elif tcpFlag == "02":
        Flag = "SYN"
    elif tcpFlag == "03":
        Flag = "FIN-SYN"
    elif tcpFlag == "08":
        Flag = "PSH"
    elif tcpFlag == "09":
        Flag = "FIN-PSH"
    elif tcpFlag == "0A":
        Flag = "SYN-PSH"
    elif tcpFlag == "10":
        Flag = "ACK"
    elif tcpFlag == "11":
        Flag = "FIN-ACK"
    elif tcpFlag == "12":
        Flag = "SYN-ACK"
    elif tcpFlag == "18":
        Flag = "PSH-ACK"
    else:
        Flag = "OTH"
       
    
    print("IP Header: " + str(packet[0:20].hex()))
    print("Version: " + str(version) + " TTL: " + str(ttl) +
          " Protocol: " + protocol + " SrcAddr: " + str(s_addr) +
          " DestAddr: " + str(d_addr))
    print("TCP Header: " + str(packet[20:40].hex()))
    print("SrcPort: " + str(source_port) + " DestPort: " + str(dest_port) +
          " Sequence Num: " + str(sequence) + " Ack Num: " + str(acknowledgement) +
          " Tcp Flag: " + Flag)
    