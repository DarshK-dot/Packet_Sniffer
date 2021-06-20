
import socket
import textwrap
import struct



TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '


#main funtion

def main():
    con = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = con.recvfrom(65536)
        dect_mac, src_mac, proto, data = ether_frame(raw_data)
        print("\n[+] Ethernet Frame :")
        print(TAB_1 + '[+]Destination :{}, [+]Source :{}, [+]Protocol :{} '.format(dect_mac, src_mac, proto))

        # For IPv4
        if proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ip_pkt(data)
            print(TAB_1 + 'IPv4 packet :')
            print(TAB_2 + '[+]Version : {}, [+]Header Length : {}, [+]TTL : {}'.format(version, header_length, ttl))
            print(TAB_2 + '[+]Protocol : {}, [+]Source : {}, [+]Target : {}'.format(proto, src, target)+'\n')
            #for ICMP

            if proto == 1:
                (icmp_type, code, checksum, data)= icmp_pkt(data)
                print(TAB_1 + 'ICMP packet :')
                print(TAB_2 + '[+]Type : {}, [+]Code : {}, [+]Checksum : {}'.format(icmp_type, code, checksum))
                print(TAB_2 + '[+]Data :')
                print(format_multi_line(DATA_TAB_3, data))
            #for TCP

            elif proto == 6:
                (src_port, dest_port, sequence, acknowledgment, flag_ack, flag_fin, flag_psh, flag_urg, flag_rst, flag_syn, data) = tcp_segments(data)
                print(TAB_1 + 'TCP Segment: ')
                print(TAB_2 + '[+]Sourse Port No.: {}, [+] Destination Port No. : {}'.format(src_port, dest_port))
                print(TAB_2 + '[+]Sequence: {}, [+]Acknowledgment: {}'.format(sequence, acknowledgment))
                print(TAB_2 + "Flags: ")
                print(TAB_3 + '[+]ACK: {}, [+]FIN: {}, [+]PSH: {},[+]URG: {}, [+]RST: {}, [+]SYN: {}'.format(flag_ack, flag_fin, flag_psh, flag_urg, flag_rst, flag_syn))
                print(TAB_2+ "Data: ")
                print(format_multi_line(DATA_TAB_3, data))
            
            #for UDP
            elif proto == 17:
                (src_port, dest_port, size, data) = udp_segments(data)
                print(TAB_1 + 'UDP Segment: ')
                print(TAB_2 + '[+]Source Port No.:{}, [+]Destination Port No.: {}, Length: {}'.format(src_port, dest_port, size))
                
            else:
                print(TAB_1 + 'Data: ')
                print(format_multi_line(DATA_TAB_2, data))

        else:
            print(TAB_1 + 'Data: ')
            print(format_multi_line(DATA_TAB_2, data))


# unpacking the Ethernet Frame


def ether_frame(data):
    destination, source, protocol = struct.unpack('! 6s 6s H', data[:14])
    return get_mac(destination), get_mac(source), socket.htons(protocol), data[14:]

# formatting the mac Address into human readable form 

def get_mac(bytes_add):
    byte_str = map('{:02x}'.format, bytes_add)
    mac_add = ':'.join(byte_str).upper()
    return mac_add

#unpacking IPv4 data 

def ip_pkt(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:] 
    

#formatting ipv4 data into readable format

def ipv4(addr):
    return '.'.join(map(str, addr))


#unpacking ICMP packets

def icmp_pkt(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


#unpacking TCP packets
def tcp_segments(data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_ack, flag_fin, flag_psh, flag_urg, flag_rst, flag_syn, data[offset:]
    

#unpacking udp packets
def udp_segments(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

#formatting multi-line data

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(bytes) for bytes in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()
