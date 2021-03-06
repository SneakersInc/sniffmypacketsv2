#!/usr/bin/env python

import json
from common.hashmethods import *
from common.dbconnect import mongo_connect
from common.entities import pcapFile, pcapStream
from canari.maltego.message import UIMessage
from common.loadpackets import loadpackets
from common.packetParser import *
from canari.framework import configure
from canari.config import config
from common.auxtools import error_logging
import datetime

__author__ = 'catalyst256'
__copyright__ = 'Copyright 2014, sniffmypacketsv2 Project'
__credits__ = []

__license__ = 'GPL'
__version__ = '0.1'
__maintainer__ = 'catalyst256'
__email__ = 'catalyst256@gmail.com'
__status__ = 'Development'

__all__ = [
    'dotransform'
]


@configure(
    label='Load Packets from PCAP',
    description='Load packets from PCAP',
    uuids=['sniffMyPacketsv2.v2.pcap_2_packets'],
    inputs=[('[SmP] - PCAP', pcapFile)],
    debug=True
)
def dotransform(request, response):

    pcap = request.value
    usedb = config['working/usedb']
    # Check to see if we are using the database or not
    if usedb == 0:
        return response + UIMessage('You have chosen not to use a database')
    else:
        pass

    d = mongo_connect()
    c = d['PACKETS']
    y = d['PACKETSUMMARY']
    url = config['web/server'].strip('\'')
    port = config['web/port'].strip('\'')

    # Hash the pcap file
    try:
        md5pcap = md5_for_file(pcap)
    except Exception as e:
        return response + UIMessage(str(e))

    def convert_encoding(data, encoding='utf-8'):
        if isinstance(data, dict):
            return dict((convert_encoding(key), convert_encoding(value)) \
                        for key, value in data.iteritems())
        elif isinstance(data, list):
            return [convert_encoding(element) for element in data]
        elif isinstance(data, unicode):
            return data.encode(encoding, errors='replace')
        else:
            return data

    # Get the PCAP ID for the pcap file
    try:
        s = d.INDEX.find({"MD5 Hash": md5pcap}).count()
        if s == 0:
            t = d.STREAMS.find({"MD5 Hash": md5pcap}).count()
            if t > 0:
                r = d.STREAMS.find({"MD5 Hash": md5pcap}, {"PCAP ID": 1, "Stream ID": 1, "_id": 0})
                for i in r:
                    pcap_id = i['PCAP ID']
                    streamid = i['Stream ID']
            else:
                return response + UIMessage('No PCAP ID, you need to index the pcap file')
        if s > 0:
            r = d.INDEX.find({"MD5 Hash": md5pcap}, {"PCAP ID": 1, "_id": 0})
            for i in r:
                pcap_id = i['PCAP ID']
                streamid = i['PCAP ID']
    except Exception as e:
        return response + UIMessage(str(e))


    stream_url = 'http://%s:%s/pcap/%s/packets' % (url, port, streamid)
    pkts = loadpackets(pcap)

    # Dump the full packets into the database for later use.
    x = find_layers(pkts, pcap, pcap_id, streamid)
    try:
        for s in x:
            tstamp = s['Buffer']['timestamp']
            q = d.PACKETS.find({"Buffer.timestamp": tstamp}).count()
            if q > 0:
                pass
            else:
                v = OrderedDict(json.loads(json.dumps(convert_encoding(s), encoding='latin-1', ensure_ascii=False)))
                c.insert(v)
    except Exception as e:
        error_logging(str(e), 'Packets')

    # Build the packet summary so we can make pretty pages.
    count = 1
    packet = OrderedDict()
    try:
        for p in pkts:
            tstamp = datetime.datetime.fromtimestamp(p.time).strftime('%Y-%m-%d %H:%M:%S.%f')
            p_header = {"PCAP ID": pcap_id, "Buffer": {"timestamp": tstamp, "packetnumber": count, "pcapfile": pcap,
                                                       "packet_length": p.len, "StreamID": streamid}}
            packet.update(p_header)
            if p.haslayer(IP):
                p_ip = {"IP": {"ip_src": p[IP].src, "ip_dst": p[IP].dst, "ip_ttl": p[IP].ttl}}
                packet.update(p_ip)
            layers = []
            counter = 0
            while True:
                layer = p.getlayer(counter)
                if layer != None:
                    if layer.name == 'HTTP':
                        pass
                    else:
                        layers.append(layer.name)
                else:
                    break
                counter += 1
            p_layers = {"Layers": layers}
            packet.update(p_layers)
            view_url = 'http://%s:%s/pcap/%s/%s/packets/%s' % (url, port, pcap_id, streamid, count)
            p_view = {"View": view_url}
            packet.update(p_view)
            t = d.PACKETSUMMARY.find({"Buffer.timestamp": tstamp}).count()
            if t > 0:
                pass
            else:
                y.insert(packet)
            count += 1
            packet.clear()
    except Exception as e:
        error_logging(str(e), 'PacketSummary')

    # Return the Maltego Entity
    a = pcapStream(stream_url)
    response += a
    return response
