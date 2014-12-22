#!/usr/bin/env python

# Part of sniffMyPackets framework.
# Generic pcap tools and utilities that SmP uses

import os
import magic
import datetime
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import rdpcap, conf


def packet_count(pcap):
    conf.verb = 0
    try:
        pkts = rdpcap(pcap)
        return len(pkts)
    except Exception as e:
        return str(e)


def check_pcap(pcap):
    try:
        bad_magic = 'pcap-ng capture file'
        m = magic.open(magic.MAGIC_NONE)
        m.load()
        f = m.file(pcap)
        if bad_magic in f:
            return 'BAD'
        else:
            return f
    except Exception as e:
        return str(e)


def count_sessions(pcap):
    try:
        pkts = rdpcap(pcap)
        return len(pkts.sessions())
    except Exception as e:
        return str(e)


def check_size(pcap):
    try:
        x = os.path.getsize(pcap)
        d = "%0.01f MB" % (x / (1024*1024.0))
        return str(d)
    except Exception as e:
        return str(e)


def get_time(pcap):
    try:
        p = rdpcap(pcap)
        c = len(p)
        start = datetime.datetime.fromtimestamp(p[0].time).strftime('%Y-%m-%d %H:%M:%S.%f')
        end = datetime.datetime.fromtimestamp(p[c -1].time).strftime('%Y-%m-%d %H:%M:%S.%f')
        return [start, end]
    except Exception as e:
        return str(e)

