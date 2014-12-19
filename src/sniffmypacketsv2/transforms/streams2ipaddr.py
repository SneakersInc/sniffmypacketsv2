#!/usr/bin/env python

from common.dbconnect import mongo_connect
from common.entities import pcapFile
from canari.maltego.entities import IPv4Address
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
    label='Extract IP Addresses',
    description='Extrac IP addresses from a pcap stream file',
    uuids=['sniffMyPacketsv2.v2.streams_2_ipaddress'],
    inputs=[('[SmP] - IP', pcapFile)],
    debug=True
)
def dotransform(request, response):

    filename = request.value

    # Connect to the database so we can search for IP addresses.
    x = mongo_connect()
    c = x['STREAMS']

    try:
        hosts = []
        r = x.STREAMS.find({'File Name': {'$regex': filename}})
        if r > 0:
            for x in r:
                hosts.append(x['Packet']['Source IP'])
                hosts.append(x['Packet']['Destination IP'])
                # streamid = x['Stream ID']
        else:
            return response + UIMessage('No records found, please make sure the pcap stream file is indexed')

        for h in hosts:
            e = IPv4Address(h)
            # e += Field('streamid', streamid, displayname='Stream ID', MatchingRule='Loose')
            response += e
        return response
    except Exception as e:
        return response + UIMessage(str(e))
