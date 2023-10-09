#!/usr/bin/env python
import scapy.all as scapy
import argparse
from scapy.layers import http


def get_arguments():

    parser = argparse.ArgumentParser()
    help_messege = "interface to be used"
    parser.add_argument("-i", "--interface", dest="interface", help=help_messege)

    (options) = parser.parse_args()

    if not options.interface:
        print("[-] interface wasn't specified, using wlan0")
        options.interface = "wlan0"

    return options


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter="port 80")


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print(packet)


def main():
    options = get_arguments()

    interface = options.interface

    sniff(interface)


main()
