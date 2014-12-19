#!/usr/bin/env python


import time
import uuid
from collections import OrderedDict
from common.dbconnect import mongo_connect
from common.pcaptools import *
from common.hashmethods import *
from canari.easygui import multenterbox
from canari.config import config
from common.entities import pcapFile, SessionID
from canari.maltego.message import Field, UIMessage
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
    label='Index PCAP File',
    description='Adds the pcap file into the database',
    uuids=['sniffmypacketsv2.v2.index_pcap_2_db'],
    inputs=[('[SmP] - PCAP', pcapFile)],
    debug=True
)
def dotransform(request, response):

    # pcap file pulled from Maltego
    pcap = request.value

    # Connect to the database so we can insert the record created below
    x = mongo_connect()
    c = x['INDEX']

    # Check the file exists first (so we don't add crap to the database
    try:
        open(pcap)
    except IOError:
        return response + UIMessage('The file doesn\'t exist')

    # Check the pcap file is in the correct format (not pcap-ng)
    try:
        f_format = check_pcap(pcap)
        if 'BAD' in f_format:
            return response + UIMessage('File format is pcap-ng, not supported by sniffMyPackets, please convert.')
    except Exception as e:
        return response + UIMessage(str(e))

    # Hash the pcap file
    try:
        md5hash = md5_for_file(pcap)
        sha1hash = sha1_for_file(pcap)
    except Exception as e:
        return response + UIMessage(str(e))

    # Get the file size
    try:
        filesize = check_size(pcap)
    except Exception as e:
        return response + UIMessage(str(e))

    # Check the pcap file doesn't exist in the database already (based on MD5 hash)
    try:
        s = x.INDEX.find({"MD5 Hash": md5hash}).count()
        if s > 0:
            r = x.INDEX.find({"MD5 Hash": md5hash}, {"PCAP ID": 1, "_id": 0})
            for i in r:
                e = SessionID(i['PCAP ID'])
                e += Field('sniffmypacketsv2.pcapfile', pcap, displayname='PCAP File')
                response += e
                return response
        else:
            pass
    except Exception as e:
        return response + UIMessage(str(e))

    # Popup message box for entering comments about the pcap file
    msg = 'Enter Comments'
    title = 'Comments'
    field_names = ["Comments"]
    field_values = []
    field_values = multenterbox(msg, title, field_names)

    # General variables used to build the index
    comments = field_values[0]
    now = time.strftime("%c")
    pcap_id = str(uuid.uuid4())[:12].replace('-', '')

    # Get a count of packets available
    try:
        pkcount = packet_count(pcap)
    except Exception as e:
        return response + UIMessage(str(e))

    # Get the start/end time of packets
    try:
        pcap_time = get_time(pcap)
    except Exception as e:
        return response + UIMessage(str(e))

    # Check for working directory, if it doesn't exist create it.
    w = config['working/directory'].strip('\'')
    try:
        if w != '':
            w = w + '/' + pcap_id
            if not os.path.exists(w):
                os.makedirs(w)
        else:
            return response + UIMessage('No working directory set, check your config file')
    except Exception as e:
        return response + UIMessage(e)

    # Build a dictonary object to upload into the database
    index = OrderedDict({'PCAP ID': pcap_id, 'PCAP Path': pcap, 'Working Directory': w, 'Upload Time': now,
                         'Comments': comments, 'MD5 Hash': md5hash, 'SHA1 Hash': sha1hash,
                         'Packet Count': pkcount, 'First Packet': pcap_time[0], 'Last Packet': pcap_time[1],
                         'File Size': filesize})

    # Insert record into the database
    c.insert(index)

    # Return the entity with Session ID into Maltego
    r = SessionID(pcap_id)
    r += Field('sniffmypacketsv2.pcapfile', pcap, displayname='PCAP File')
    response += r
    return response
