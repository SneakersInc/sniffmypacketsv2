#!/usr/bin/env python

from canari.maltego.message import Field, UIMessage
from common.dbconnect import mongo_connect
from common.entities import pcapFile, SessionID
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
    label='Import PCAPs based on Session ID',
    description='Imports all PCAP files based on Session ID',
    uuids=[ 'sniffmypacketsv2.v2.import_from_session' ],
    inputs=[ ( '[SmP] - Sessions', SessionID ) ],
    debug=True
)
def dotransform(request, response, config):
  sess = request.value
  x = mongo_connect()
  p = []

  # Query the mongoDB for pcap files (inc streams) based on SessionID
  try:
    s = x.SessionID.find({"SessionID": sess}, { "pcapfile": 1, "_id":0})
    for i in s:
      if i['pcapfile'] not in p:
        p.append(i['pcapfile'])
    u = x.StreamIndex.find({"SessionID": sess}, { "streamfile": 1, "_id":0})
    for i in u:
      if i['streamfile'] not in p:
        p.append(i['streamfile'])
  except Exception as e:
    return response + UIMessage(e)

  # Build the entities based on the generated list
  for x in p:
    e = pcapFile(x)
    e += Field('sniffmypacketsv2.SessionID', sess, displayname='Session ID')
    response += e
  return response
