#!/usr/bin/env python

import datetime
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from collections import OrderedDict
from badlayers import *
from http import *

bind_layers(TCP, HTTP)


def rename_layer(x, n):
    n = n.lower().replace(' ', '_').replace('-', '_').replace('.', '_') + '_'
    return dict((n+k.lower(), f(v) if hasattr(v, 'keys') else v) for k, v in x.items())


def find_layers(pcap):
    pkts = rdpcap(pcap)
    packet = OrderedDict()
    count = 1
    try:
        for p in pkts:
            header = {"Buffer": {"timestamp": datetime.datetime.fromtimestamp(p.time).strftime('%Y-%m-%d %H:%M:%S.%f'),
                                 "packetnumber": count, "pcapfile": pcap}}
            packet.update(header)
            counter = 0
            while True:
                layer = p.getlayer(counter)
                if layer != None:
                    i = int(counter)
                    x = p[0][i].fields
                    t = exclude_layers(x, layer.name)
                    s = rename_layer(t, layer.name)
                    v = '{"' + layer.name.replace('.', '_') + '[' + str(i) + ']' + '":' + str(s) + '}'
                    s = eval(v)
                    packet.update(s)
                else:
                    break
                counter += 1
            count += 1
            yield packet
            packet.clear()
    except Exception as e:
        pass