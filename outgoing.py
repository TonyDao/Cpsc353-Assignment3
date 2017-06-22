#!/usr/bin/env python

from scapy.all import *
import socket

def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

def lookup(addr):
    try:
        return socket.gethostbyaddr(addr)[0]
    except socket.herror:
        return None

DST_ADDRESS = []
IP_ADDRESS = get_ip_address()

def summarize(pkt):
    global DST_ADDRESS
    global IP_ADDRESS

    # get source and destination IP
    if IP in pkt:
        ip_src=pkt[IP].src
        ip_dst=pkt[IP].dst
    # get source and destination TCP
    if TCP in pkt:
        tcp_src = pkt[TCP].sport
        tcp_dst = pkt[TCP].dport

    # check IP from this IP
    if pkt[IP].src == IP_ADDRESS:
        # add IP in list when IP is first visiting
        if ip_dst not in DST_ADDRESS:
            DST_ADDRESS.append(ip_dst)
            hostname = lookup(ip_dst)
            if hostname:
                print hostname
            else:
                print ip_dst

sniff(prn=summarize, store=0)
