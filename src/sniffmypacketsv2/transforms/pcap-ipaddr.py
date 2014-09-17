#!/usr/bin/env python

import os
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.dbconnect import mongo_connect
from collections import OrderedDict
from canari.maltego.message import Field, Label, UIMessage
from common.entities import pcapFile, Host
from canari.framework import configure #, superuser

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

#@superuser
@configure(
    label='Extract IP Addresses',
    description='Extract IP addresses from pcap file',
    uuids=[ 'sniffmypacketsv2.v2.pcap_2_ipaddr' ],
    inputs=[ ( '[SmP] - PCAP', pcapFile ) ],
    debug=True
)
def dotransform(request, response, config):
  pcap = request.value
  sess =request.fields['sniffmypacketsv2.SessionID']
  pkts = rdpcap(pcap)
  # Set the lists to be used
  tcp_srcip = []
  udp_srcip = []
  convo = []

  # Pull out all the TCP and UDP IP addresses
  for p in pkts:
    if p.haslayer(TCP):
      tcp_srcip.append(p.getlayer(IP).src)
    if p.haslayer(IP) and p.haslayer(UDP):
      udp_srcip.append(p.getlayer(IP).src)

  for x in tcp_srcip:
    talker = x, str(tcp_srcip.count(x)), 'tcp'
    if talker not in convo:
      convo.append(talker)

  for y in udp_srcip:
    talker = y, str(udp_srcip.count(y)), 'udp'
    if talker not in convo:
      convo.append(talker)

  # Write to the database and build the entities
  for t in convo:
    try:
      x = mongo_connect()
      c = x['IPAddress']
      v = OrderedDict()
      header = {"SessionID": sess, "pcapfile": pcap, "ipaddr": t[0], "proto": t[2]}
      v.update(header)
      c.insert(v)
    except Exception as e:
      return response + UIMessage(e)
    e = Host(t[0])
    e.linklabel = t[2]
    e += Field('sniffmypacketsv2.pcapfile', pcap, displayname='Original pcap File')
    e += Field('sniffmypacketsv2.SessionID', sess, displayname='SessionID', matchingrule='loose')
    response += e
  return response
