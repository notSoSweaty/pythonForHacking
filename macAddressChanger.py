#!/user/bin/env python

import subprocess
import optparse
import re

def get_arguments():

    parser = optparse.OptionParser()
    interface_help_messege = "Interface to change its MAC address. The interface here is wlp2s0"
    parser.add_option("-i", "--interface", dest="interface", help=interface_help_messege)
    parser.add_option("-m", "--mac", dest="new_mac", help="New MAC address")

    (options, arguments) = parser.parse_args()

    if not options.interface:
        # Put in a default interface wlp2s0
        options.interface = "wlp2s0"
        print("default interface of wlp2s0 will be applied")
    if not options.new_mac:
        # put in default mac F4:CE:46:23:a8
        options.new_mac = "F4:CE:46:23:A8:56"
        # make "newMac" random in future
        print("default MAC address of F4:CE:46:23:A8 will be applied")

    return options


def change_mac(interface, newMac):

    print("[+] Changing MAC address for " + interface + " to " + newMac)

    subprocess.call(["ifconfig", interface, "down"])  # cleaned up user input
    subprocess.call(["ifconfig", interface, "hw", "ether", newMac])
    subprocess.call(["ifconfig", interface, "up"])


def clean_ifconfig(interface):

    ifconfig_result = subprocess.check_output(["ifconfig", interface])
    cleaner_mac = ifconfig_result.decode()
    cleaned_mac = re.search(r'\w\w:\w\w:\w\w:\w\w:\w\w:\w\w', cleaner_mac)
    if cleaned_mac:
        return ("[+] The MAC address is now " + cleaned_mac.group(0))
    else:
        print("[-] Could not read MAC address.")


options = get_arguments()
change_mac(options.interface, options.new_mac)
cleaned_mac = clean_ifconfig(options.interface)
print(cleaned_mac)
