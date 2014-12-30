#!/usr/bin/env python

from common.dbconnect import mongo_connect
from common.entities import pcapFile
from canari.framework import configure
from canari.maltego.entities import IPv4Address
from canari.maltego.message import UIMessage

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
    label='Return IPv4 Address(s)',
    description='Return IPv4 Addresses from Session ID',
    uuids=['sniffMyPacketsv2.v2.session_2_ipaddr'],
    inputs=[('[SmP] - Sessions', pcapFile)],
    debug=True
)
def dotransform(request, response):

    pcap = request.value
    x = mongo_connect()
    ipaddr = []

    try:
        r = x.STREAMS.find({"File Name": pcap}).count()
        if r > 0:
            p = x.STREAMS.find({"File Name": pcap}, {"Packet.Source IP": 1, "Packet.Destination IP": 1, "_id": 0})
            for i in p:
                sip = i['Packet']['Source IP']
                dip = i['Packet']['Destination IP']
                ipaddr.append(sip)
                ipaddr.append(dip)
        else:
            return response + UIMessage('This needs to be run from a TCP/UDP stream')
    except Exception as e:
        return response + UIMessage(str(e))

    for t in ipaddr:
        e = IPv4Address(t)
        response += e
    return response