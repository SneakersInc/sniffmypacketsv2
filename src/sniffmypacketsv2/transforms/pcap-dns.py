#!/usr/bin/env python
import os
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.dbconnect import mongo_connect
from collections import OrderedDict
from canari.maltego.message import Field, Label, UIMessage
from common.entities import pcapFile, DomainName
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
    label='Find DNS Traffic',
    description='Find DNS traffic in a pcap file',
    uuids=[ 'sniffmypacketsv2.v2.pcap_2_dns' ],
    inputs=[ ( '[SmP] - PCAP', pcapFile ) ],
    debug=True
)
def dotransform(request, response, config):
  # Set system variables
  pcap = request.value
  sess = ''
  x = mongo_connect()
  dns = []

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

  # Load the pcap into Scapy
  pkts = rdpcap(pcap)
  # Look for DNS packets (requests & responses)
  for p in pkts:
    if p.haslayer(DNSRR):
      a_count = p[DNS].ancount
      i = a_count + 4
      while i > 4:
        r = 'Response', p[0][i].rrname, p[0][i].rdata, p[0][i].ttl
        dns.append(r)
        i -= 1
    if p.haslayer(DNSQR):
      r = 'Request', p[DNSQR].qname, p[IP].src, p[DNSQR].qtype
      dns.append(r)

  # Build entities
  for d in dns:
    e = DomainName(d[1])
    e.linklabel = d[0]
    response += e
  return response
