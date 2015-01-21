#!/usr/bin/env python

# Welcome to Gobbler, the Scapy pcap parser and dump scripts
# Part of the sniffMyPackets suite http://www.sniffmypackets.net
# Written by @catalyst256 / catalyst256@gmail.com

import datetime
from layers.http import *
from layers.BadLayers import *
from common.auxtools import error_logging
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from collections import OrderedDict

bind_layers(TCP, HTTP)


def rename_layer(x, n):
    n = n.lower().replace(' ', '_').replace('-', '_').replace('.', '_') + '_'
    return dict((n+k.lower(), f(v) if hasattr(v, 'keys') else v) for k, v in x.items())


def find_layers(pkts, pcap, pcap_id, streamid):
    packet = OrderedDict()
    count = 1
    pcap_id = pcap_id.encode('utf-8')
    streamid = streamid.encode('utf-8')
    try:
        for p in pkts:
            header = {"Buffer": {"timestamp": datetime.datetime.fromtimestamp(p.time).strftime('%Y-%m-%d %H:%M:%S.%f'),
                                 "packetnumber": count, "PCAP ID": pcap_id, "pcapfile": pcap, "StreamID": streamid}}
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
                    try:
                        del s['HTTP[3]']
                        del s['HTTP[5]']
                    except KeyError:
                        pass
                    packet.update(s)
                else:
                    break
                counter += 1
            count += 1
            yield packet
            packet.clear()
    except Exception as e:
        error_logging(str(e), 'PacketParser')
        pass



