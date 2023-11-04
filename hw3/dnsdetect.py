import argparse
import netifaces as ni
from scapy.all import *

def dnsdetect(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNSRR) and pkt[DNS].qr == 1: # checks if packet is is a dns query response packet
        src = pkt[IP].src
        dst = pkt[IP].dst
        dns_id = pkt[DNS].id
        dns_qd = pkt[DNS].qd
        dns_rdata = pkt[DNSRR].rdata
        dns_qname = dns_qd.qname.rstrip(".")
        if len(captured_dict) != 0 and dns_id in captured_dict:
            captured_pkt = captured_dict[dns_id]
            prev_src = captured_pkt[IP].src
            prev_dst = captured_pkt[IP].dst
            prev_dns_id = captured_pkt[DNS].id
            prev_dns_qd = captured_pkt[DNS].qd
            prev_dns_rdata = captured_pkt[DNSRR].rdata
            prev_dns_qname = prev_dns_qd.qname.rstrip(".")
            if prev_src == src and prev_dst == dst and prev_dns_qname == dns_qname and prev_dns_rdata != dns_rdata:
                legit_ip_list = []
                bad_ip_list = []
                for i in range(pkt['DNS'].ancount): # ancount = dns answer count
                    dnsrr = pkt['DNS'].an[i] # each dnsrr from packet
                    if dnsrr.type == 1: # if dnsrr type == 'A'
                        legit_ip_list.append(dnsrr.rdata)

                for i in range(captured_pkt['DNS'].ancount): # same thing with sus packet
                    dnsrr = captured_pkt['DNS'].an[i]
                    if dnsrr.type == 1:
                        bad_ip_list.append(dnsrr.rdata)

                if legit_ip_list != bad_ip_list: # an additional check
                    f.write(time.strftime("%m %d %Y %H:%M:%S\n"))
                    f.write(f"TXID {prev_dns_id} Request {prev_dns_qname}\n")
                    f.write(f"Answer1 {legit_ip_list}\n")
                    f.write(f"Answer2 {bad_ip_list}\n")
        else:
            captured_dict[dns_id]=pkt



if __name__ == "__main__":
    parser = argparse.ArgumentParser(conflict_handler="resolve")
    parser.add_argument('-i', dest="interface", default=scapy.interfaces.get_working_if()) # default for interface is an interface that works :D
    parser.add_argument('-r', dest="tracefile")

    args = parser.parse_args()
    d = vars(args)
    captured_dict = {}

    try:
        f = open("log.txt", "w")
    except:
        print("failed to open file: log.txt")

    if d["tracefile"] != None:
        sniff(filter="udp dst port 53 and udp[10] & 0x80 = 0", offline=d["tracefile"], prn=dnsdetect, store=False)
    else:
        sniff(filter="udp dst port 53 and udp[10] & 0x80 = 0", iface=d["interface"], prn=dnsdetect, store=False)