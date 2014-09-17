#!/usr/bin/env python
import time
import uuid
from collections import OrderedDict
from common.dbconnect import mongo_connect
from common.entities import pcapFile, SessionID
from canari.maltego.message import Field, Label, UIMessage
# from canari.maltego.utils import debug, progress
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
    label='Generate Session ID',
    description='Generates Session ID for pcap file',
    uuids=[ 'sniffmypacketsv2.v2.create_session_id_2_db' ],
    inputs=[ ( '[SmP] - PCAP', pcapFile ) ],
    debug=True
)
def dotransform(request, response, config):
  pcap = request.value
  now = time.strftime("%c")
  sess_id = str(uuid.uuid4()).replace('-', '')
  x = mongo_connect()
  c = x['SessionID']
  try:
    s = x.SessionID.find({"pcapfile": request.value}).count()
    if s > 0:
      r = x.SessionID.find({"pcapfile": request.value}, { "SessionID": 1, "_id":0})
      for i in r:
        e = SessionID(i['SessionID'])
        e += Field('sniffmypacketsv2.pcapfile', pcap, displayname='PCAP File')
        response += e
        return response
    else:
      v = OrderedDict()
      header = {"SessionID": sess_id, "pcapfile": pcap, "timestamp": now}
      v.update(header)
      c.insert(v)
  except Exception, e:
    return response + UIMessage(e)
  r = SessionID(sess_id)
  r += Field('sniffmypacketsv2.pcapfile', pcap, displayname='PCAP File')
  response += r
  return response
