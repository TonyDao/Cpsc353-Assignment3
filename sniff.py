#!/usr/bin/env python

from scapy.all import *

def summarize(pkt):
    print pkt.summary()

sniff(prn=summarize, store=0)
