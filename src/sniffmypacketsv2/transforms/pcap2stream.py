#!/usr/bin/env python

from common.hashmethods import *
from common.dbconnect import mongo_connect
from common.entities import pcapFile, pcapStream
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
    label='Extract Stream Info',
    description='Extract Stream information',
    uuids=['sniffMyPacketsv2.v2.stream2info'],
    inputs=[('[SmP] - Streams', pcapFile)],
    debug=True
)
def dotransform(request, response):
    pcap = request.value

    # Connect to the database so we can insert the record created below
    x = mongo_connect()
    c = x['STREAMS']

    # Hash the pcap file
    try:
        md5hash = md5_for_file(pcap)
    except Exception as e:
        return response + UIMessage(str(e))

    # Get the working directory & pcap id
    try:
        s = x.STREAMS.find({"MD5 Hash": md5hash}).count()
        if s > 0:
            r = x.STREAMS.find({"MD5 Hash": md5hash}, {"Folder": 1, "_id": 0})
            for i in r:
                folder = i['Folder']
        else:
            return response + UIMessage('No Stream ID, you need to index the pcap file')
    except Exception as e:
        return response + UIMessage(str(e))

    l = len(folder) + 1
    raw = pcap[l:-5]
    raw = raw.split('-')
    banner = 'Protocol:%s\nSource:%s\nDestination:%s' % (raw[0], raw[1], raw[2])
    e = pcapStream(banner)
    response += e
    return response
