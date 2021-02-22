import socket
import argparse
import struct
import binascii

def main():
    conn = socket.socket(socket.IPPROTO_UDP, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        if eth_proto == "IPV4":
            printPacketsV4(data, raw_data)
            # version, header_length, ttl, proto, src, target, data = ipv4_Packet(data)
            # if src == "192.168.29.128":
            #     print("UDPEeee")
            


def printPacketsV4(data, raw_data):
    version, header_length, ttl, proto, src, target, data = ipv4_Packet(data)
    if proto == 17 and src == "127.0.0.1":
        print("*******************UDPv4***********************")
        print("Version: {}\nLength: {}\n TTL: {}".format(version, header_length, ttl))
        print("Protocol: {}\nSource: {}\nDestination: {}".format(proto, src, target))
        src_port, dest_port, length, data = udp_seg(data)
        print("*****UDP Segment*****")
        print("Source Port: {}\nDestination Port: {}\nLength: {}\nData: {}".format(src_port, dest_port, length, data))



def udp_seg(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]



def ipv4_Packet(data):
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_len, ttl, proto, ipv4(src), ipv4(target), data[header_len:]


def ipv4(addr):
    return '.'.join(map(str, addr))


def ethernet_frame(data):
    proto = ""
    IpHeader = struct.unpack("!6s6sH", data[0:14])
    dstMac = binascii.hexlify(IpHeader[0])
    srcMac = binascii.hexlify(IpHeader[1])
    protoType = IpHeader[2]
    nextProto = hex(protoType)

    if nextProto == '0x800':
        proto = 'IPV4'
    elif nextProto == '0x86dd':
        proto = 'IPV6'
    
    data = data[14:]
    return dstMac, srcMac, proto, data


if __name__ == "__main__":
    main()