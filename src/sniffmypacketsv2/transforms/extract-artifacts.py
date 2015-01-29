#!/usr/bin/env python


from canari.framework import configure
from common.dbconnect import mongo_connect, find_session
from common.hashmethods import *
from common.auxtools import check_file
from common.protocols.dissector import *
from common.entities import pcapFile, Artifact
from canari.config import config
import uuid
from canari.maltego.message import Field, UIMessage
import glob


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
    usedb = config['working/usedb']
    # Check to see if we are using the database or not
    if usedb > 0:
        # Connect to the database so we can insert the record created below
        d = mongo_connect()
        c = d['ARTIFACTS']
        # Hash the pcap file
        try:
            md5pcap = md5_for_file(pcap)
        except Exception as e:
            return response + UIMessage(str(e))
        x = find_session(md5pcap)
        pcap_id = x[0]
        folder = x[2]
    else:
        w = config['working/directory'].strip('\'')
        try:
            if w != '':
                w = w + '/' + str(uuid.uuid4())[:12].replace('-', '')
                if not os.path.exists(w):
                    os.makedirs(w)
                folder = w
            else:
                return response + UIMessage('No working directory set, check your config file')
        except Exception as e:
            return response + UIMessage(e)

    folder = '%s/%s' % (folder, 'artifacts')

    if not os.path.exists(folder):
        os.makedirs(folder)

    dissector = Dissector() # instance of dissector class
    dissector.change_dfolder(folder)
    dissector.dissect_pkts(pcap)
    list_files = glob.glob(folder+'/*')
    # print list_files

    # Loop through the stored files and create the database/maltego objects
    for g in list_files:
        try:
            md5hash = md5_for_file(g)
            sha1hash = sha1_for_file(g)
            ftype = check_file(g)
            n = len(folder) + 1
            l = len(g)
            filename = g[n:l]
            if usedb > 0:
                data = {'PCAP ID': pcap_id, 'Path': folder, 'File Name': filename, 'File Type': ftype, 'MD5 Hash': md5hash,
                        'SHA1 Hash': sha1hash}
                t = d.ARTIFACTS.find({'MD5 Hash': md5hash, "File Name": filename}).count()
                if t > 0:
                    pass
                else:
                    c.insert(data)
            else:
                pass

            # Create the Maltego entities
            a = Artifact(filename)
            a.ftype = ftype
            a.fhash = md5hash
            a += Field('path', folder, displayname='Path')
            response += a
        except Exception as e:
            print str(e)

    return response
