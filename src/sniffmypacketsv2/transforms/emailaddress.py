#!/usr/bin/env python

from common.dbconnect import mongo_connect, find_session
from common.hashmethods import *
from common.entities import pcapFile
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from canari.maltego.entities import EmailAddress
from canari.maltego.message import UIMessage
from canari.framework import configure
import re
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
    usedb = config['working/usedb']
    # Check to see if we are using the database or not
    if usedb > 0:
        d = mongo_connect()
        c = d['CREDS']
        # Hash the pcap file
        try:
            md5pcap = md5_for_file(pcap)
        except Exception as e:
            return response + UIMessage(str(e))
        x = find_session(md5pcap)
        pcap_id = x[0]
    else:
        pass
    addr = []
    try:
        for p in pkts:
            for m in lookfor:
                if p.haslayer(TCP) and p.haslayer(Raw):
                    raw = p[Raw].load
                    if m in raw:
                        for s in re.finditer('<([\S.-]+@[\S-]+)>', raw):
                            addr.append(s.group(1))
    except Exception as e:
        return response + UIMessage(str(e))

    for x in addr:
        if usedb > 0:
            data = {'PCAP ID': pcap_id, 'Type': 'Email Address', 'Record': x}
            t = d.CREDS.find({'Record': x}).count()
            if t > 0:
                pass
            else:
                c.insert(data)
        else:
            pass
        e = EmailAddress(x)
        response += e
    return response
