#!/usr/bin/env python

import datetime
import logging

from sniffmypacketsv2.transforms.common.layers.http import *
from common.dbconnect import mongo_connect, find_session
from common.hashmethods import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from collections import OrderedDict
from common.entities import pcapFile
from canari.framework import configure
from canari.maltego.entities import Website
from canari.maltego.message import UIMessage
from canari.config import config

bind_layers(TCP, HTTP)

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
    label='Find HTTP Requests',
    description='Find HTTP Requests in a PCAP file',
    uuids=['sniffMyPacketsv2.v2.pcap_2_http'],
    inputs=[('[SmP] - HTTP', pcapFile)],
    debug=True
)
def dotransform(request, response):

    # Store the pcap file as a variable
    pcap = request.value
    usedb = config['working/usedb']
    # Check to see if we are using the database or not
    if usedb > 0:
        # Connect to the database so we can insert the record created below
        x = mongo_connect()
        c = x['HTTP']

        # Hash the pcap file
        try:
            md5hash = md5_for_file(pcap)
        except Exception as e:
            return response + UIMessage(str(e))

        d = find_session(md5hash)
        pcap_id = d[0]
    else:
        pass

    # Find HTTP Requests
    pkts = rdpcap(pcap)
    http_requests = []
    for p in pkts:
        if p.haslayer(HTTPRequest):
            timestamp = datetime.datetime.fromtimestamp(p.time).strftime('%Y-%m-%d %H:%M:%S.%f')
            r = p[HTTPRequest].Host
            if usedb > 0:
                http = OrderedDict({'PCAP ID': pcap_id,
                                    'Time Stamp': timestamp,
                                    'Type': 'HTTP Request', 'IP': {'src': p[IP].src, 'dst': p[IP].dst},
                                    'HTTP': {'Method': p[HTTPRequest].Method, 'URI': p[HTTPRequest].Path,
                                             'Referer': p[HTTPRequest].Referer, 'Host': p[HTTPRequest].Host}})
                # Check if record already exists
                s = x.HTTP.find({'Time Stamp': timestamp}).count()
                if s > 0:
                    pass
                else:
                    c.insert(http)
            if r not in http_requests:
                http_requests.append(r)
        else:
            pass

    for i in http_requests:
        h = Website(i)
        response += h
    return response