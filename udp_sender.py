import socket
from scapy.all import rdpcap, sendp
import time

pcap_path = '/home/hcrl/Downloads/FINAL_DATASET/attack_dataset/SOMEIP_interface_spoofing_attack_ATTACK.pcap'
pkts = rdpcap(pcap_path)

def send_receive_packet(pkts, ip, port):
    udp_sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    # udp_sock.bind(('0.0.0.0', 5000))

    for pkt in pkts:
        
        raw_bytes = bytes(pkt)
        udp_sock.sendto(raw_bytes, (ip, port))
        time.sleep(1)

send_receive_packet(pkts, '192.168.137.132', 50000)

