#!/usr/bin/env python

import re
from common.dbconnect import mongo_connect
from common.hashmethods import *
from common.entities import pcapFile
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from canari.maltego.entities import EmailAddress
from canari.maltego.message import UIMessage
from canari.framework import configure

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
    label='Extract Email Address(s)',
    description='Extract email addresses from a pcap file',
    uuids=['sniffMyPacketsv2.v2.pcap_2_emailaddr'],
    inputs=[('[SmP] - Email', pcapFile)],
    debug=True
)
def dotransform(request, response):
    pcap = request.value
    lookfor = ['MAIL FROM:', 'RCPT TO:']
    pkts = rdpcap(pcap)

    d = mongo_connect()
    c = d['CREDS']

    # Hash the pcap file
    try:
        md5pcap = md5_for_file(pcap)
    except Exception as e:
        return response + UIMessage(str(e))

    # Get the PCAP ID for the pcap file
    try:
        s = d.INDEX.find({"MD5 Hash": md5pcap}).count()
        if s == 0:
            t = d.STREAMS.find({"MD5 Hash": md5pcap}).count()
            if t > 0:
                r = d.STREAMS.find({"MD5 Hash": md5pcap}, {"PCAP ID": 1, "_id": 0})
                for i in r:
                    pcap_id = i['PCAP ID']
            else:
                return response + UIMessage('No PCAP ID, you need to index the pcap file')
        if s > 0:
            r = d.INDEX.find({"MD5 Hash": md5pcap}, {"PCAP ID": 1, "_id": 0})
            for i in r:
                pcap_id = i['PCAP ID']
    except Exception as e:
        return response + UIMessage(str(e))

    addr = []

    try:
        for p in pkts:
            for m in lookfor:
                if p.haslayer(TCP) and p.haslayer(Raw):
                    raw = p[Raw].load
                    if m in raw:
                        for s in re.finditer('<([\S.-]+@[\S-]+)>', raw):
                            addr.append(s.group(1))
                            # print s.group(1)
    except Exception as e:
        return response + UIMessage(str(e))

    for x in addr:
        data = {'PCAP ID': pcap_id, 'Type': 'Email', 'Record': x}
        t = d.CREDS.find({'Record': x}).count()
        if t > 0:
            pass
        else:
            c.insert(data)
        e = EmailAddress(x)
        response += e
    return response
