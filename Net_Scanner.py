#!/usr/bin/env python

import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP or IP range")
    options = parser.parse_args()

    return options


def scanner(ip):
    arpRequest = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arpRequestBroadcast = broadcast/arpRequest
    answered_List = scapy.srp(arpRequestBroadcast, timeout=2, verbose=False)[0]
# list cleaner below
    device_list = []
    for index in answered_List:
        device_dict = {"ip": index[1].psrc, "mac": index[1].hwsrc}
        device_list.append(device_dict)

    return device_list


def print_result(results_list):
    print("IP\t\t\t\tMAC Address")
    print("---------------------------------------------------------")
    for index in results_list:
        print(index["ip"] + "\t\t\t" + index["mac"])
        print("---------------------------------------------------------")


options = get_arguments()
user_target = options.target
device_list = scanner(user_target)
print_result(device_list)