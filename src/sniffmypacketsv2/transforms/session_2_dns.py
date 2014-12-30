#!/usr/bin/env python

from common.dbconnect import mongo_connect
from common.entities import pcapFile
from canari.framework import configure
from canari.maltego.entities import Website
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
    label='Return DNS Requests',
    description='Return DNS Requests from Session ID',
    uuids=['sniffMyPacketsv2.v2.session_2_dns'],
    inputs=[('[SmP] - Sessions', pcapFile)],
    debug=True
)
def dotransform(request, response):

    pcap = request.value
    x = mongo_connect()

    try:
        r = x.STREAMS.find({"File Name": pcap}).count()
        if r > 0:
            p = x.STREAMS.find({"File Name": pcap}, {"Stream ID": 1, "_id": 0})
            for i in p:
                sessionid = i['Stream ID']
        else:
            return response + UIMessage('This needs to be run from a TCP/UDP stream')
    except Exception as e:
        return response + UIMessage(str(e))

    try:
        t = x.DNS.find({"Stream ID": sessionid}).count()
        if t > 0:
            p = x.DNS.find({"Stream ID": sessionid}, {"Request Details.Query Name": 1, "_id": 0})
            for i in p:
                e = Website(i['Request Details']['Query Name'])
                response += e
            return response
        else:
            return response + UIMessage('No DNS records found')
    except Exception as e:
        return response + UIMessage(str(e))