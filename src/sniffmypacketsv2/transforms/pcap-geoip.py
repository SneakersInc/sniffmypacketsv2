#!/usr/bin/env python

from common.entities import pcapFile, GeoMap
from common.dbconnect import mongo_connect
from common.hashmethods import *
import datetime
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from collections import OrderedDict
from common.geoip import lookup_geo
from canari.maltego.message import UIMessage
from canari.framework import configure
from canari.config import config

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
    label='Lookup GeoIP Details',
    description='TODO: Returns a Something entity with the phrase "Hello Word!"',
    uuids=['sniffMyPacketsv2.v2.pcap_2_geoip'],
    inputs=[('[SMP] - GeoIP', pcapFile)],
    debug=True
)
def dotransform(request, response):

    # Store the pcap file as a variable
    pcap = request.value

    # Connect to the database so we can insert the record created below
    x = mongo_connect()
    c = x['GEOIP']

    # Hash the pcap file
    try:
        md5hash = md5_for_file(pcap)
    except Exception as e:
        return response + UIMessage(str(e))

    # Get the PCAP ID for the pcap file
    try:
        s = x.INDEX.find({"MD5 Hash": md5hash}).count()
        if s == 0:
            t = x.STREAMS.find({"MD5 Hash": md5hash}).count()
            if t > 0:
                r = x.STREAMS.find({"MD5 Hash": md5hash}, {"PCAP ID": 1, "_id": 0})
                for i in r:
                    pcap_id = i['PCAP ID']
            else:
                return response + UIMessage('No PCAP ID, you need to index the pcap file')
        if s > 0:
            r = x.INDEX.find({"MD5 Hash": md5hash}, {"PCAP ID": 1, "_id": 0})
            for i in r:
                pcap_id = i['PCAP ID']
    except Exception as e:
        return response + UIMessage(str(e))

    # Load the pcap file and look for IP addresses, then GeoIP them
    convo = []
    pkts = rdpcap(pcap)
    for p in pkts:
        if p.haslayer(IP) and p.haslayer(TCP):
            proto = 'TCP'
            s = proto, p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport
            r = proto, p[IP].dst, p[TCP].dport, p[IP].src, p[TCP].sport
            if s not in convo:
                convo.append(s)
            if r in convo:
                convo.remove(r)
        else:
            pass
        if p.haslayer(IP) and p.haslayer(UDP):
            proto = 'UDP'
            s = proto, p[IP].src, p[UDP].sport, p[IP].dst, p[UDP].dport
            r = proto, p[IP].dst, p[UDP].dport, p[IP].src, p[UDP].sport
            if s not in convo:
                convo.append(s)
            if r in convo:
                convo.remove(r)
        else:
            pass

    # Run each IP through a GeoIP lookup and build a directory object to insert into the database
    for proto, src, sport, dst, dport in convo:
        s = lookup_geo(src)
        d = lookup_geo(dst)
        geo = OrderedDict({'PCAP ID': pcap_id, 'Protocol': proto, 'src': src, 'src port': sport, 'src geo': s,
                           'dst': dst, 'dst port': dport, 'dst geo': d})

        t = x.GEOIP.find({'src': src, 'src port': sport, 'dst': dst, 'dst port': dport}).count()
        if t > 0:
            pass
        else:
            c.insert(geo)

    # Build the URL for the returned Maltego entity
    url = config['web/server'].strip('\'')
    port = config['web/port'].strip('\'')
    map_url = 'http://%s:%s/pcap/%s/map' % (url, port, pcap_id)
    e = GeoMap(map_url)
    response += e
    return response
