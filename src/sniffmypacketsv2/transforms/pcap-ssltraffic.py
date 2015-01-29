#!/usr/bin/env python

import binascii
import datetime
from common.hashmethods import *
from common.dbconnect import mongo_connect, find_session
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile
from canari.maltego.message import UIMessage
from canari.maltego.entities import Website
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
    label='Find SSL Traffic',
    description='Looks for SSL connections within a pcap',
    uuids=['sniffMyPacketsv2.v2.pcap_2_ssltraffic'],
    inputs=[('[SmP] - SSL', pcapFile)],
    debug=True
)
def dotransform(request, response):
    pcap = request.value
    usedb = config['working/usedb']
    # Check to see if we are using the database or not
    if usedb > 0:
        # Connect to the database so we can insert the record created below
        d = mongo_connect()
        c = d['SSL']

        # Hash the pcap file
        try:
            md5hash = md5_for_file(pcap)
        except Exception as e:
            return response + UIMessage(str(e))
        d = find_session(md5hash)
        pcap_id = d[0]
    else:
        pass

    # Load the packets
    pkts = rdpcap(pcap)
    # Look for SSL packets and pull out the required information.
    servers = []
    try:
        for p in pkts:
            if p.haslayer(IP) and p.haslayer(TCP) and p.haslayer(Raw):
                x = p[Raw].load
                x = hexstr(x)
                x = x.split(' ')
                if x[0] == '16':
                    timestamp = datetime.datetime.fromtimestamp(p.time).strftime('%Y-%m-%d %H:%M:%S.%f')
                    stype = 'Handshake'
                    if x[5] == '01':
                        htype = 'Client Hello'
                        slen = int(''.join(x[131:133]), 16)
                        s = 133 + slen
                        sname = binascii.unhexlify(''.join(x[133:s]))
                        if sname not in servers:
                            servers.append(sname)
                        if usedb > 0:
                            data = {'PCAP ID': pcap_id, 'SSL Type': stype, 'Handshake Type': htype,
                                    'Time Stamp': timestamp,
                                    'Source IP': p[IP].src, 'Source Port': p[TCP].sport, 'Destination IP': p[IP].dst,
                                    'Destination Port': p[TCP].dport, 'Server Name': sname}
                            t = d.SSL.find({'Time Stamp': timestamp}).count()
                            if t > 0:
                                pass
                            else:
                                c.insert(data)
                        else:
                            pass

                    if x[5] == '02':
                        htype = 'Server Hello'
                        ctype = ''.join(x[76:78])
                        if usedb > 0:
                            data = {'PCAP ID': pcap_id, 'SSL Type': stype, 'Handshake Type': htype,
                                    'Time Stamp': timestamp,
                                    'Source IP': p[IP].src, 'Source Port': p[TCP].sport, 'Destination IP': p[IP].dst,
                                    'Destination Port': p[TCP].dport, 'Cipher Suite': ctype}
                            t = d.SSL.find({'Time Stamp': timestamp}).count()
                            if t > 0:
                                pass
                            else:
                                c.insert(data)
                        else:
                            pass
                    else:
                        pass
            else:
                pass
    except Exception as e:
        return response + UIMessage(str(e))

    # Return Maltego entities based on the SSL server name
    for s in servers:
        e = Website(s)
        response += e
    return response
