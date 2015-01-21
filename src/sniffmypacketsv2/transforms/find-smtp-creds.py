#!/usr/bin/env python

from common.dbconnect import mongo_connect
from common.hashmethods import *
from canari.maltego.message import UIMessage
from common.findcreds import smtp_creds
from common.entities import pcapFile, Credential
from canari.framework import configure

__author__ = 'catalyst256'
__copyright__ = 'Copyright 2015, sniffmypacketsv2 Project'
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
    label='Find SMTP Credentials',
    description='Look for SMTP Credentials',
    uuids=['sniffMyPacketsv2.v2.find_smtp_creds'],
    inputs=[('[SmP] - Email', pcapFile)],
    debug=True
)
def dotransform(request, response):

    pcap = request.value
    # Connect to the database so we can insert the record created below
    x = mongo_connect()
    c = x['CREDS']

    # Hash the pcap file
    try:
        md5pcap = md5_for_file(pcap)
    except Exception as e:
        return response + UIMessage(str(e))

    # Get the PCAP ID for the pcap file
    try:
        s = x.INDEX.find({"MD5 Hash": md5pcap}).count()
        if s == 0:
            t = x.STREAMS.find({"MD5 Hash": md5pcap}).count()
            if t > 0:
                r = x.STREAMS.find({"MD5 Hash": md5pcap}, {"PCAP ID": 1, "_id": 0})
                for i in r:
                    pcap_id = i['PCAP ID']
            else:
                return response + UIMessage('No PCAP ID, you need to index the pcap file')
        if s > 0:
            r = x.INDEX.find({"MD5 Hash": md5pcap}, {"PCAP ID": 1, "_id": 0})
            for i in r:
                pcap_id = i['PCAP ID']
    except Exception as e:
        return response + UIMessage(str(e))

    d = smtp_creds(pcap)
    if len(d) == 0:
        return response + UIMessage('No SMTP Credentials found..sorry')

    for n in d:
        data = {'PCAP ID': pcap_id, 'Type': 'Email Credential', 'Record': n}
        t = x.CREDS.find({'Record': n}).count()
        if t > 0:
            pass
        else:
            c.insert(data)

        e = Credential(n)
        response += e
    return response