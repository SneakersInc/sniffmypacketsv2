#!/usr/bin/env python

import requests
import time
from canari.config import config
from common.entities import Artifact
from canari.framework import configure
from canari.maltego.message import UIMessage
from common.dbconnect import mongo_connect
from common.hashmethods import *

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
    label='Upload file to Web Server',
    description='Uploads a file to the web server',
    uuids=['sniffMyPacketsv2.v2.artifact_2_web'],
    inputs=[('[SmP] - Artifacts', Artifact)],
    debug=True
)
def dotransform(request, response):

    filename = request.value
    folder = request.fields['path']
    usedb = config['working/usedb']
    # Check to see if we are using the database or not
    if usedb == 0:
        return response + UIMessage('No database support configured, check your config file')
    else:
        pass

    # Build the web server variables
    url = config['web/server'].strip('\'')
    port = config['web/port'].strip('\'')
    upload_url = 'http://%s:%s/pcap/_uploads' % (url, port)

    # Connect to the database so we can insert the record created below
    x = mongo_connect()
    c = x['FILES']

    now = time.strftime("%c")
    zipfile = '%s/%s' % (folder, filename)

    # Hash the pcap file
    try:
        md5hash = md5_for_file(zipfile)
        sha1hash = sha1_for_file(zipfile)
    except Exception as e:
        return response + UIMessage(str(e))

    # Get the PCAP ID for the pcap file
    try:
        s = x.ARTIFACTS.find({"MD5 Hash": md5hash}).count()
        if s > 0:
            r = x.ARTIFACTS.find({"MD5 Hash": md5hash}, {"File Type": 1, "PCAP ID": 1, "_id": 0})
            for i in r:
                pcap_id = i['PCAP ID']
                ftype = i['File Type']
        else:
            return response + UIMessage('No PCAP ID, you need to index the pcap file')
    except Exception as e:
        return response + UIMessage(str(e))

    download_url = 'http://%s:%s/pcap/downloads/%s' % (url, port, filename)

    # Check to see if the file is already uploaded

    s = c.find({'File Name': filename}).count()
    if s > 0:
        return response + UIMessage('File already uploaded!!')
    else:
        data = {'Upload Time': now, 'File Name': filename, 'Folder': folder, 'MD5 Hash': md5hash, 'SHA1 Hash': sha1hash,
                'Download': download_url, 'PCAP ID': pcap_id, 'File Type': ftype}

    try:
        # Create the POST request to upload the file
        files = {'files': open(zipfile, 'rb')}
        r = requests.post(upload_url, files=files)
        if r.status_code == 200:
            c.insert(data)
            return response + UIMessage('File Uploaded!!')
        else:
            return response + UIMessage(str(r.status_code))
    except Exception as e:
        return response + UIMessage(str(e))
