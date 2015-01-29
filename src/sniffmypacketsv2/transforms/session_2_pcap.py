#!/usr/bin/env python

from common.dbconnect import mongo_connect
from common.entities import SessionID, pcapFile
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
    label='Return PCAP File',
    description='Return PCAP file from Session ID',
    uuids=['sniffMyPacketsv2.v2.session_2_pcap'],
    inputs=[('[SmP] - Sessions', SessionID)],
    debug=True
)
def dotransform(request, response):
    sessionid = request.value
    usedb = config['working/usedb']
    # Check to see if we are using the database or not
    if usedb == 0:
        return response + UIMessage('No database support configured, check your config file')
    else:
        pass
    x = mongo_connect()
    try:
        r = x.INDEX.find({"PCAP ID": sessionid}).count()
        if r > 0:
            p = x.INDEX.find({"PCAP ID": sessionid}, {"_id": 0})
            for i in p:
                pcap = i['PCAP Path']
                s = pcapFile(pcap)
                response += s
                return response
        else:
            return response + UIMessage('PCAP not found, is the SessionID correct??')
    except Exception as e:
        return response + UIMessage(str(e))