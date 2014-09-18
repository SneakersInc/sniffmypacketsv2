#!/usr/bin/env python

import os
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.dbconnect import mongo_connect
from collections import OrderedDict
from canari.maltego.message import Field, Label, UIMessage
from canari.maltego.entities import IPv4Address
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
  # Set the base variables
  sess = ''
  x = mongo_connect()

  # Look to see if the pcap file has a SessionID value already
  try:
    s = x.SessionID.find({"pcapfile": request.value}).count()
    if s > 0:
      r = x.SessionID.find({"pcapfile": request.value}, { "SessionID": 1, "_id":0})
      for i in r:
        sess = i['SessionID']
    if s == 0:
      r = x.StreamIndex.find({"streamfile": request.value}).count()
      if r > 0:
        d = x.StreamIndex.find({"streamfile": request.value}, { "SessionID": 1, "_id":0})
        for i in d:
          sess = i['SessionID']
      else:
        return response + UIMessage('No SessionID found, you need to generate one!!')
  except Exception as e:
    return response + UIMessage(e)

  # Load the pcap file into scapy as variable pkts
  pcap = request.value
  pkts = rdpcap(pcap)

  # Set the lists to be used
  tcp_srcip = []
  udp_srcip = []
  convo = []

  # Pull out all the TCP and UDP IP addresses
  for p in pkts:
    if p.haslayer(TCP):
      tcp_srcip.append(p.getlayer(IP).src)
      tcp_srcip.append(p.getlayer(IP).dst)
    if p.haslayer(UDP):
      udp_srcip.append(p.getlayer(IP).src)
      udp_srcip.append(p.getlayer(IP).dst)

  for m in tcp_srcip:
    talker = m, 'tcp'
    if talker not in convo:
      convo.append(talker)

  for y in udp_srcip:
    talker = y, 'udp'
    if talker not in convo:
      convo.append(talker)

  # Write to the database
  for ip, proto in convo:
    try:
      c = x['IPAddress']
      v = OrderedDict()
      header = {"SessionID": sess, "pcapfile": pcap, "ipaddr": ip, "proto": proto}
      v.update(header)
      c.insert(v)
    except Exception as e:
      return response + UIMessage(e)
    # Build the entities
    e = Host(ip)
    e.linklabel = proto
    e += Field('sniffmypacketsv2.pcapfile', pcap, displayname='Original pcap File', matchingrule='loose')
    e += Field('sniffmypacketsv2.SessionID', sess, displayname='SessionID', matchingrule='loose')
    response += e
  return response
