#!/usr/bin/env python

import glob
from common.dbconnect import mongo_connect
from common.hashmethods import *
import magic
from common.dissectors.dissector import *
from canari.maltego.message import UIMessage
from common.entities import pcapFile, Artifact
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
    label='Extract files',
    description='Extract files from pcap file',
    uuids=['sniffMyPacketsv2.v2.pcap_2_artifacts'],
    inputs=[('[SmP] - Artifacts', pcapFile)],
    debug=True
)
def dotransform(request, response):

    pcap = request.value
    folder = ''
    # Connect to the database so we can insert the record created below
    d = mongo_connect()
    c = d['ARTIFACTS']

    # Hash the pcap file
    try:
        md5pcap = md5_for_file(pcap)
    except Exception as e:
        return response + UIMessage(str(e))

    # Get the PCAP ID for the pcap file
    try:
        s = d.INDEX.find({"MD5 Hash": md5pcap}).count()
        if s == 0:
            t = d.STREAMS.find({"MD5 Hash": md5pcap}).count()
            if t > 0:
                r = d.STREAMS.find({"MD5 Hash": md5pcap}, {"PCAP ID": 1, "Folder": 1, "_id": 0})
                for i in r:
                    pcap_id = i['PCAP ID']
                    folder = i['Folder']

            else:
                return response + UIMessage('No PCAP ID, you need to index the pcap file')
        if s > 0:
            r = d.INDEX.find({"MD5 Hash": md5pcap}, {"PCAP ID": 1, "Working Directory": 1,  "_id": 0})
            for i in r:
                pcap_id = i['PCAP ID']
                folder = i['Working Directory']
    except Exception as e:
        return response + UIMessage(str(e))

    folder = '%s/%s' % (folder, 'artifacts')

    if not os.path.exists(folder):
        os.makedirs(folder)

    # list_files = []

    dissector = Dissector() # instance of dissector class
    dissector.change_dfolder(folder)
    dissector.dissect_pkts(pcap)
    list_files = glob.glob(folder+'/*')

    # Loop through the stored files and create the database/maltego objects
    for i in list_files:
        try:
            md5hash = md5_for_file(i)
            sha1hash = sha1_for_file(i)
            ftype = magic.from_file(i)
            k = len(folder) + 1
            l = len(i)
            filename = i[k:l]
            data = {'PCAP ID': pcap_id, 'Path': folder, 'File Name': filename, 'File Type': ftype, 'MD5 Hash': md5hash,
                    'SHA1 Hash': sha1hash}
            t = d.ARTIFACTS.find({'MD5 Hash': md5hash}).count()
            if t > 0:
                pass
            else:
                c.insert(data)
            # Create the Maltego entities
            a = Artifact(filename)
            a.ftype = ftype
            a.fhash = md5hash
            response += a
        except Exception as e:
            pass

    return response