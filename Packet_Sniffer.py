#!/usr/bin/env python
import scapy.all as scapy
import argparse


def get_arguments():

    parser = argparse.ArgumentParser()
    help_messege = "This script will aid in MitM attacks as the packet sniffer"
    parser.add_argument("-i", "--interface", dest="interface", help=help_messege)

    (options, arguments) = parser.parse_args()

    return options

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    print(packet)


sniff("wlan0")
