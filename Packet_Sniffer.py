#!/usr/bin/env python
import scapy.all as scapy
import argparse


def get_arguments():

    parser = argparse.ArgumentParser()
    help_messege = "interface to be used"
    parser.add_argument("-i", "--interface", dest="interface", help=help_messege)

    (options) = parser.parse_args()

    if not options.interface:
        parser.error("[-] interface wasn't specified, using wlan0")
        options.interface = "wlan0"

    return options


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    print(packet)


def main():
    options = get_arguments()

    interface = options.interface

    sniff(interface)


main()
