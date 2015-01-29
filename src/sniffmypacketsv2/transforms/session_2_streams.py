#!/usr/bin/env python

from common.dbconnect import mongo_connect
from common.entities import pcapFile
from canari.framework import configure
from canari.maltego.message import UIMessage
from canari.config import config

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
    label='Return TCP/UDP Streams',
    description='Return TCP/UDP streams from Session ID',
    uuids=['sniffMyPacketsv2.v2.session_2_streams'],
    inputs=[('[SmP] - Sessions', pcapFile)],
    debug=True
)
def dotransform(request, response):

    pcap = request.value
    usedb = config['working/usedb']
    # Check to see if we are using the database or not
    if usedb == 0:
        return response + UIMessage('No database support configured, check your config file')
    else:
        pass
    x = mongo_connect()

    try:
        r = x.INDEX.find({"PCAP Path": pcap}).count()
        if r > 0:
            p = x.INDEX.find({"PCAP Path": pcap}, {"PCAP ID": 1, "_id": 0})
            for i in p:
                sessionid = i['PCAP ID']
        else:
            return response + UIMessage('PCAP not found, is the SessionID correct??')
    except Exception as e:
        return response + UIMessage(str(e))

    try:
        s = x.STREAMS.find({"PCAP ID": sessionid}).count()
        if s > 0:
            p = x.STREAMS.find({"PCAP ID": sessionid}, {"File Name": 1, "_id": 0})
            for i in p:
                fname = i['File Name']
                q = pcapFile(fname)
                response += q
            return response
        else:
            return response + UIMessage('No streams found for that Session ID')
    except Exception as e:
        return response + UIMessage(str(e))
