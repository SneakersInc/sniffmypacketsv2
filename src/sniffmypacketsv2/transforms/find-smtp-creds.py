#!/usr/bin/env python

from common.dbconnect import mongo_connect, find_session
from common.hashmethods import *
from canari.maltego.message import UIMessage
from common.findcreds import smtp_creds
from common.entities import pcapFile, Credential
from canari.framework import configure
from canari.config import config

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
    usedb = config['working/usedb']
    # Check to see if we are using the database or not
    if usedb > 0:
        # Connect to the database so we can insert the record created below
        x = mongo_connect()
        c = x['CREDS']

        # Hash the pcap file
        try:
            md5pcap = md5_for_file(pcap)
        except Exception as e:
            return response + UIMessage(str(e))
        d = find_session(md5pcap)
        pcap_id = d[0]
    else:
        pass

    d = smtp_creds(pcap)
    if len(d) == 0:
        return response + UIMessage('No SMTP Credentials found..sorry')
    for n in d:
        if usedb > 0:
            data = {'PCAP ID': pcap_id, 'Type': 'Email Credential', 'Record': n}
            t = x.CREDS.find({'Record': n}).count()
            if t > 0:
                pass
            else:
                c.insert(data)
        else:
            pass
        e = Credential(n)
        response += e
    return response