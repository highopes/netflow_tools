"""
This module has the functions to deal with the data exported from Netflow v5 devices
"""

'''
netflow v5 header format
Bytes    Contents    Description
0-1      version    NetFlow export format version number
2-3      count    Number of flows exported in this packet (1-30)
4-7      sys_uptime    Current time in milliseconds since the export device booted
8-11     unix_secs    Current count of seconds since 0000 UTC 1970
12-15    unix_nsecs    Residual nanoseconds since 0000 UTC 1970
16-19    flow_sequence    Sequence counter of total flows seen
20       engine_type    Type of flow-switching engine
21       engine_id    Slot number of the flow-switching engine
22-23    sampling_interval    First two bits hold the sampling mode; remaining 14 bits hold value of sampling interval
netflow v5 record format
0-3      srcaddr    Source IP address
4-7      dstaddr    Destination IP address
8-11     nexthop    IP address of next hop router
12-13    input    SNMP index of input interface
14-15    output    SNMP index of output interface
16-19    dPkts    Packets in the flow
20-23    dOctets    Total number of Layer 3 bytes in the packets of the flow
24-27    first    SysUptime at start of flow
28-31    last    SysUptime at the time the last packet of the flow was received
32-33    srcport    TCP/UDP source port number or equivalent
34-35    dstport    TCP/UDP destination port number or equivalent
36       pad1    Unused (zero) bytes
37       tcp_flags    Cumulative OR of TCP flags
38       prot    IP protocol type (for example, TCP = 6; UDP = 17)
39       tos    IP type of service (ToS)
40-41    src_as    Autonomous system number of the source, either origin or peer
42-43    dst_as    Autonomous system number of the destination, either origin or peer
44       src_mask    Source address prefix mask bits
45       dst_mask    Destination address prefix mask bits
46-47    pad2    Unused (zero) bytes
'''


import socket, struct

from socket import inet_ntoa

SIZE_OF_HEADER = 24
SIZE_OF_RECORD = 48

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 9999))

while True:
    buf, addr = sock.recvfrom(1500)

    uptime = socket.ntohl(struct.unpack('I',buf[4:8])[0])
    epochseconds = socket.ntohl(struct.unpack('I',buf[8:12])[0])

    (version, count) = struct.unpack('!HH',buf[0:4])
    if version != 5:
        print "Not NetFlow v5!"
        continue

    # It's pretty unlikely you'll ever see more then 1000 records in a 1500 byte UDP packet
    if count <= 0 or count >= 1000:
        print "Invalid count %s" % count
        continue

    sample=struct.unpack('!H',buf[22:24])[0]
    samplebits= map(int,((sample & 0xc0)>>6,sample & 0x3f))


    print "Netflow UDP exported time %s"%(uptime)
    print "sampelmode:%s samplerate:%s "%(samplebits[0],samplebits[1])
    print "flow counts exported =%s"%(count)
    print "---------------------------------------------------------------------------------------------------------------------"

    for i in range(0, count):
        try:
            base = SIZE_OF_HEADER+(i*SIZE_OF_RECORD)

            data = struct.unpack('!IIIIHH',buf[base+16:base+36])

            nfdata = {}
            nfdata['saddr'] = inet_ntoa(buf[base+0:base+4])
            nfdata['daddr'] = inet_ntoa(buf[base+4:base+8])
            nfdata['pcount'] = data[0]
            nfdata['bcount'] = data[1]
            nfdata['stime'] = data[2]
            nfdata['etime'] = data[3]
            nfdata['sport'] = data[4]
            nfdata['dport'] = data[5]
            nfdata['protocol'] = ord(buf[base+38])

            print "%s:%s -> %s:%s   start:%s - stop:%s  = packet:%s bytes:%s  protocol:%s" % (nfdata['saddr'],nfdata['sport'],nfdata['daddr'],nfdata['dport'],nfdata['stime'],nfdata['etime'],nfdata['pcount'],nfdata['bcount'],nfdata['protocol'])

        except:
            continue

    # Do something with the netflow record..
    print "---------------------------------------------------------------------------------------------------------------------"