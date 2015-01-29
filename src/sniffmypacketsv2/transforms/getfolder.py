#!/usr/bin/env python

from common.dbconnect import mongo_connect
from common.entities import SessionID, Folder
from canari.maltego.message import UIMessage, Field
from canari.framework import configure
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
    label='Get Folder',
    description='Return the working directory for the session',
    uuids=['sniffMyPacketsv2.v2.get_folder_2_maltego'],
    inputs=[('[SmP] - Sessions', SessionID)],
    debug=True
)
def dotransform(request, response):

    pcap_id = request.value
    usedb = config['working/usedb']
    # Check to see if we are using the database or not
    if usedb == 0:
        return response + UIMessage('No database support configured, check your config file')
    else:
        pass
    # Connect to the database so we can insert the record created below
    x = mongo_connect()
    c = x['INDEX']

    try:
        s = c.find({'PCAP ID': pcap_id}).count()
        if s > 0:
            r = c.find({'PCAP ID': pcap_id}, {'Working Directory': 1, '_id': 0})
            for i in r:
                folder = i['Working Directory']
    except Exception as e:
        return response + UIMessage(str(e))

    e = Folder(folder)
    e += Field('sessionid', pcap_id, displayname='Session ID')
    response += e
    return response
