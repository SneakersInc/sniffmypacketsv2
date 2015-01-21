#!/usr/bin/env python

import datetime
from common.dbconnect import mongo_connect
from common.hashmethods import *
import tldextract
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from collections import OrderedDict
from common.entities import pcapFile
from canari.maltego.entities import Domain
from canari.maltego.message import UIMessage
from canari.framework import configure
from common.auxtools import error_logging

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
    label='Find DNS Domains',
    description='Find DNS Domains in a pcap file',
    uuids=['sniffMyPacketsv2.v2.pcap_2_dnsdomains'],
    inputs=[('[SmP] - DNS', pcapFile)],
    debug=True
)
def dotransform(request, response):
    # Store the pcap file as a variable
    pcap = request.value

    # Connect to the database so we can insert the record created below
    x = mongo_connect()
    c = x['DNS']

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
                r = x.STREAMS.find({"MD5 Hash": md5hash}, {"PCAP ID": 1, "Stream ID": 1, "_id": 0})
                for i in r:
                    pcap_id = i['PCAP ID']
                    session_id = i['Stream ID']

            else:
                return response + UIMessage('No PCAP ID, you need to index the pcap file')
        if s > 0:
            r = x.INDEX.find({"MD5 Hash": md5hash}, {"PCAP ID": 1, "_id": 0})
            for i in r:
                pcap_id = i['PCAP ID']
                session_id = i['PCAP ID']
    except Exception as e:
        return response + UIMessage(str(e))

    # Find the DNS requests and responses
    try:
        pkts = rdpcap(pcap)
        dns_requests = []
        for p in pkts:
            if p.haslayer(DNSQR):
                timestamp = datetime.datetime.fromtimestamp(p.time).strftime('%Y-%m-%d %H:%M:%S.%f')
                r = p[DNSQR].qname[:-1]
                tld = tldextract.extract(r)
                domain = tld.registered_domain
                # print domain
                dns = OrderedDict({'PCAP ID': pcap_id, 'Stream ID': session_id,
                                   'Time Stamp': timestamp,
                                   'Type': 'Request', 'IP': {'src': p[IP].src, 'dst': p[IP].dst, 'length': p[IP].len},
                                   'Request Details': {'Query Type': p[DNSQR].qtype, 'Query Name': r, 'Domain': domain}})
                t = x.DNS.find({'Time Stamp': timestamp}).count()
                if t > 0:
                    pass
                else:
                    c.insert(dns)
                if r not in dns_requests:
                    dns_requests.append(domain)
            else:
                pass
    
        for d in dns_requests:
            x = Domain(d)
            response += x
        return response

    except Exception as e:
        error_logging(str(e), 'DNS Requests')
