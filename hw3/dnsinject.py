import argparse
import netifaces as ni
from scapy.all import *

def get_ip(ifname):
    # for reference: ni.ifaddresses('eth0') outputs
    # -> {2: [{'broadcast': '172.17.255.255', 'addr': '172.17.0.2', 'mask': '255.255.0.0'}], 17: [{'addr': '02:42:ac:11:00:02', 'broadcast': 'ff:ff:ff:ff:ff:ff'}]}
    ip = ni.ifaddresses(ifname)[ni.AF_INET][0]['addr']
    return ip

def dnsinject(packet):
    print("i am printing:", type(packet))
    # if packet.haslayer(IP) and packet.haslayer(DNSQR) and packet[DNS].qr == 0:
        # host = packet[DNSQR].qname # hostname of DNSQR
        # print("host: ", host)
        # if d["hostfile"] != None:
        #     ip = 


if __name__ == "__main__":
    parser = argparse.ArgumentParser(conflict_handler="resolve")
    parser.add_argument('-i', dest="interface", default=scapy.interfaces.get_working_if()) # default for interface is an interface that works
    parser.add_argument('-h', dest="hostfile")
    args = parser.parse_args() # Example: (python3 dnsinject.py -> Namespace(interface=<NetworkInterface eth0 [UP+BROADCAST+RUNNING+SLAVE]>, hostsmap=None))
    d = vars(args) # access Namespace dict

    ip_mapping = {}

    # whether hostfile specified or not
    if d["hostfile"] == None:
        redir = get_ip(str(d["interface"]))
        print(redir)
    else:
        redir = ""
        file = open(d["hostfile"], "r")
        for line in file:
            hostnames = line.split(',')
            ip_mapping[hostnames[1].strip()] = hostnames[0].strip() # set hostnames to their respective ip as dict
        print(ip_mapping)

    
    # sniff(filter="dns", iface=d["interface"], prn=dnsinject, store=False, count=5) # remove count later
    sniff(iface=d["interface"], prn=dnsinject, store=False, count=5)

    # print(d)
