import sys
import time
import threading
from datetime import datetime
from scapy.all import *
from collections import defaultdict
from ipaddress import ip_network, ip_address
from prettytable import PrettyTable
import os
import logging
import argparse

attacks = defaultdict(list)

def process_packet(packet):
    global attacks
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        sinkhole_network = ip_network("192.168.1.0/24")

        if ip_address(dst_ip) not in sinkhole_network:
            packet_type = ""
            if ICMP in packet:
                packet_type = "ICMP"
            elif TCP in packet:
                packet_type = "TCP"
                dst_port = packet[TCP].dport
            elif UDP in packet:
                packet_type = "UDP"
                dst_port = packet[UDP].dport

            attacks[(src_ip, dst_ip)].append((dst_port if packet_type != 'ICMP' else 'N/A', packet_type))
            logging.info(f'[{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}]: Source: {src_ip}, Destination: {dst_ip}, Protocol: {packet_type}, Port: {dst_port if packet_type != "ICMP" else "N/A"}')

def clear_terminal():
    if os.name == 'posix':
        os.system('clear')
    elif os.name == 'nt':
        os.system('cls')

def display_results():
    while True:
        clear_terminal()
        print(f"Attaques détectées ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')}):\n")

        table = PrettyTable()
        table.field_names = ["Source", "Destination", "Ports", "Type"]
        for (src_ip, dst_ip), attacks_list in attacks.items():
            if attacks_list:
                ports_list = list(set([attack[0] for attack in attacks_list]))
                ports_list = ports_list[-3:] if len(ports_list) > 3 else ports_list
                if len(ports_list) < len([attack[0] for attack in attacks_list]):
                    ports_str = ', '.join([str(port) for port in ports_list]) + f", +{len([attack[0] for attack in attacks_list]) - len(ports_list)} autres"
                else:
                    ports_str = ', '.join([str(port) for port in ports_list])
                table.add_row([src_ip, dst_ip, ports_str, attacks_list[-1][1]])

        print(table)
        time.sleep(0.5)

def main(iface, log_file):
    logging.basicConfig(filename=log_file, level=logging.INFO)

    print(f"[*] Démarrage du sinkhole sur l'interface {iface}...")
    try:
        t = threading.Thread(target=sniff, kwargs={'iface': iface, 'prn': process_packet, 'store': False, 'filter': "ip", 'promisc': True})
        t.start()
        display_results()
    except KeyboardInterrupt:
        print("\n[*] Arrêt du sinkhole...")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Démarrage du sinkhole.")
    parser.add_argument('-i', '--interface', help='Interface réseau à surveiller', required=True)
    parser.add_argument('-l', '--log', help='Chemin du fichier de log', default='sinkhole.log')
    args = parser.parse_args()

    main(args.interface, args.log)
