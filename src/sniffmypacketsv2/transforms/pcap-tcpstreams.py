#!/usr/bin/env python

import os
import hashlib
import re
import time
from common.dbconnect import mongo_connect
from canari.config import config
from common.entities import pcapFile, SessionID
from canari.maltego.message import Field, Label, UIMessage
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
    label='Extract TCP Streams',
    description='Extract TCP Streams from a pcap',
    uuids=[ 'sniffmypacketsv2.v2.pcap_2_tcp_streams' ],
    inputs=[ ( '[SmP] - PCAP', pcapFile ) ],
    debug=True
)
def dotransform(request, response, config):
  pcap = request.value
  sess = ''
  x = mongo_connect()

  # Look to see if the pcap file has a SessionID value already
  try:
    s = x.SessionID.find({"pcapfile": request.value}).count()
    if s > 0:
      r = x.SessionID.find({"pcapfile": request.value}, { "SessionID": 1, "_id":0})
      for i in r:
        sess = i['SessionID']
    else:
      return response + UIMessage('No SessionID found, you need to generate one!!')
  except Exception as e:
    return response + UIMessage(e)

  # Check for working directory, if it doesn't exist create it.
  w = config['working/directory'].strip('\'')
  try:
    if w != '':
      w = w + '/' + sess
      if not os.path.exists(w):
        os.makedirs(w)
    else:
      return response + UIMessage('No working directory set, check your config file')
  except Exception as e:
    return response + UIMessage(e)

  # Generate TCP stream index
  stream_index = []
  stream_file = []

  # Create a list of the streams in the pcap file and save them as an index
  cmd = 'tshark -r ' + pcap + ' -T fields -e tcp.stream'
  p = os.popen(cmd).readlines()
  for z in p:
    if z not in stream_index:
      stream_index.append(z)

  # Create the raw pcap files for each tcp stream found
  try:
    for y in stream_index:
      y = y.strip('\n')
      dumpfile = w + '/tcp-stream' + y + '.dump'
      if 'tcp-stream.dump' in dumpfile:
        pass
      else:
        cmd = 'tshark -r ' + pcap + ' -Y \'tcp.stream eq ' + y + '\' -w ' + dumpfile
        if dumpfile not in stream_file:
          stream_file.append(dumpfile)
          os.popen(cmd)
  except:
    pass

  # Run each file through editcap to force the pcap format to pcap (libpcap), using regex to allow for user defined working directory
  for s in stream_file:
    files = re.findall('tcp-stream[0-9]{1,}', s)
    for f in files:
      cut = w + '/' + f + '.pcap'
      cmd = 'editcap -F pcap ' + s + ' ' + cut
      os.popen(cmd)
      remove = 'rm ' + s
      os.popen(remove)

      # Dump the information into the database.
      try:
        c = x['StreamIndex']
        now = time.strftime("%c")
        m = {}
        h = {"SessionID": sess, "streamfile": f, "timestamp": now, "filepath": w, "originalpcap": pcap}
        m.update(h)
        c.insert(m)
      except:
        pass

      # Create the entities
      e = pcapFile(cut)
      e += Field('sniffmypacketsv2.pcapfile', request.value, displayname='PCAP File', matchingrule='loose')
      e += Field('sniffmypacketsv2.folder', w, displayname='Folder', matchingrule='loose')
      e += Field('sniffmypacketsv2.SessionID', sess, displayname='SessionID', matchingrule='loose')
      response += e
  return response
