#!/usr/bin/env python

from common.pcapstreams import create_streams
from collections import OrderedDict
from common.pcaptools import *
from common.hashmethods import *
from common.dbconnect import mongo_connect
from common.entities import pcapFile
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
    label='Get TCP/UDP Streams',
    description='Extract TCP/UDP streams from pcap file',
    uuids=[ 'sniffMyPackets.v2.pcap_2_streams'],
    inputs=[('[SmP] - PCAP', pcapFile)],
    debug=True
)
def dotransform(request, response):
    pcap = request.value
    folder = ''
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
        s = x.INDEX.find({"MD5 Hash": md5hash}).count()
        if s > 0:
            r = x.INDEX.find({"MD5 Hash": md5hash}, {"PCAP ID": 1, "Working Directory": 1, "_id": 0})
            for i in r:
                pcap_id = i['PCAP ID']
                folder = i['Working Directory']
        else:
            return response + UIMessage('No PCAP ID, you need to index the pcap file')
    except Exception as e:
        return response + UIMessage(str(e))

    # Create TCP/UDP stream files
    s = create_streams(pcap, folder)
    for i in s:

        # Get a count of packets available
        try:
            pkcount = packet_count(i)
        except Exception as e:
            return response + UIMessage(str(e))

        # Get the start/end time of packets
        try:
            pcap_time = get_time(i)
        except Exception as e:
            return response + UIMessage(str(e))

        # Hash the pcap file
        try:
            md5hash = md5_for_file(i)
            sha1hash = sha1_for_file(i)
        except Exception as e:
            return response + UIMessage(str(e))

        # Pull out the details of the packets
        l = len(folder) + 1
        raw = i[l:-5]
        pkt = raw.replace('-', ' ').replace(':', ' ').split()

        # Create the dictonary object to insert into database
        data = OrderedDict({'Parent ID': pcap_id, 'Folder': folder, 'Packet Count': pkcount, 'File Name': i,
                            'First Packet': pcap_time[0], 'Last Packet': pcap_time[1], 'MD5 Hash': md5hash,
                            'SHA1 Hash': sha1hash, 'Packet': {'Protocol': pkt[0], 'Source IP': pkt[1],
                                                              'Source Port': pkt[2], 'Destination IP': pkt[3],
                                                              'Destination Port': pkt[4]}})

        # Check to see if the record exists
        try:
            t = x.STREAMS.find({"File Name": i}).count()
            if t > 0:
                pass
            else:
                c.insert(data)
        except Exception as e:
            return response + UIMessage(str(e))

    # Create Maltego entities for each pcap file
    for p in s:
        l = len(folder) + 1
        p = p[l:-5]
        e = pcapFile(p)
        response += e
    return response
