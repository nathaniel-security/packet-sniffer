import socket
from general import *
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.icmp import ICMP
from networking.tcp import TCP
from networking.udp import UDP
from networking.pcap import Pcap
from networking.http import HTTP

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '


def main():
    pcap = Pcap('capture.pcap')
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        print("\n****************************************************************\n")
        raw_data, addr = conn.recvfrom(65535)
        pcap.write(raw_data)
        eth = Ethernet(raw_data)
        #print(eth)

        print('\nEthernet Frame:')
        print('Destination: {} \n Source: {} \n Protocol: {}'.format(eth.dest_mac, eth.src_mac, eth.proto))

        # IPv4
        if eth.proto == 8:
            ipv4 = IPv4(eth.data)
            print('IPv4 Packet:')
            print('Version: {} \n Header Length: {} \n TTL: {} \n'.format(ipv4.version, ipv4.header_length, ipv4.ttl))
            print('\n Protocol: {} \n Source: {} \n Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))

            # ICMP
            if ipv4.proto == 1:
                icmp = ICMP(ipv4.data)
                print('ICMP Packet:')
                print('\n Type: {} \n Code: {} \n Checksum: {} \n'.format(icmp.type, icmp.code, icmp.checksum))
                print('\n ICMP Data:')
                print(format_multi_line(DATA_TAB_3, icmp.data))

            # TCP
            elif ipv4.proto == 6:
                tcp = TCP(ipv4.data)
                print('\n TCP Segment:')
                print('Source Port: {} \n Destination Port: {} \n'.format(tcp.src_port, tcp.dest_port))
                print('Sequence: {} \n Acknowledgment: {} \n'.format(tcp.sequence, tcp.acknowledgment))
                print('\n Flags:')
                print('URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
                print('RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))

                if len(tcp.data) > 0:

                    # HTTP
                    if tcp.src_port == 80 or tcp.dest_port == 80:
                        print('\n HTTP Data:')
                        try:
                            http = HTTP(tcp.data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:
                                print(DATA_TAB_3 + str(line))
                        except:
                            print(format_multi_line(DATA_TAB_3, tcp.data))
                    else:
                        print('TCP Data:')
                        print(format_multi_line('\n',tcp.data))

            # UDP
            elif ipv4.proto == 17:
                udp = UDP(ipv4.data)
                print('UDP Segment:')
                print('\n Source Port: {} \n Destination Port: {} \n Length: {}'.format(udp.src_port, udp.dest_port, udp.size))

            # Other IPv4
            else:
                print('\n Other IPv4 Data:')
                print(format_multi_line(DATA_TAB_2, ipv4.data))

        else:
            print('\nEthernet Data:')
            print(format_multi_line(DATA_TAB_1, eth.data))

        print("\n##############################################################\n")

    pcap.close()


main()
