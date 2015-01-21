#!/usr/bin/env python

# Part of sniffMyPackets framework.

import re
import binascii
import base64
from auxtools import error_logging
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


# Base functions that we will use to check the packets for interesting stuff


def check_ascii(s):
    try:
        a = s.decode('ascii')
        return a
    except UnicodeDecodeError:
        pass


def decode_base64(s):
    try:
        x = base64.decodestring(s)
        return x
    except binascii.Error:
        pass


# Look for various type of credentials stored in packets.as


def smtp_creds(pcap):
    strings = []
    output = []
    try:
        pkts = rdpcap(pcap)
        for p in pkts:
            if p.haslayer(TCP) and p.haslayer(Raw) and p.getlayer(TCP).dport == 25:
                load = p[Raw].load
                if load not in strings:
                    strings.append(load)
                else:
                    pass
            else:
                pass
    except Exception as e:
        error_logging(str(e), 'SMTP Creds')

    for s in strings:
        t = decode_base64(s)
        if t is not None:
            c = check_ascii(t)
            if c is not None and len(c) > 3:
                output.append(c)
            else:
                pass
        else:
            pass

    return output


