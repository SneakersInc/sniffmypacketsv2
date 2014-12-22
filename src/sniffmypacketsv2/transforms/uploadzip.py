#!/usr/bin/env python

import requests
import time
from canari.config import config
from common.entities import ZipFile
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
    label='Upload ZipFile to Web Server',
    description='Uploads the zip file to the web server',
    uuids=['sniffMyPacketsv2.v2.zipfile_2_web'],
    inputs=[('[SmP] - Sessions', ZipFile)],
    debug=True
)
def dotransform(request, response):

    zipfile = request.value
    folder = request.fields['folder']
    pcap_id = request.fields['sessionid']
    # Build the web server variables
    url = config['web/server'].strip('\'')
    port = config['web/port'].strip('\'')
    upload_url = 'http://%s:%s/pcap/_uploads' % (url, port)

    # Connect to the database so we can insert the record created below
    x = mongo_connect()
    c = x['FILES']

    now = time.strftime("%c")

    # Hash the pcap file
    try:
        md5hash = md5_for_file(zipfile)
        sha1hash = sha1_for_file(zipfile)
    except Exception as e:
        return response + UIMessage(str(e))

    f = len(folder) + 1
    filename = zipfile[f:]
    download_url = 'http://%s:%s/pcap/downloads/%s' % (url, port, filename)

    # Check to see if the file is already uploaded

    s = c.find({'File Name': filename}).count()
    if s > 0:
        return response + UIMessage('File already uploaded!!')
    else:
        data = {'Upload Time': now, 'File Name': filename, 'Folder': folder, 'MD5 Hash': md5hash, 'SHA1 Hash': sha1hash,
                'Download': download_url, 'PCAP ID': pcap_id}


    try:
        # Create the POST request to upload the file
        files = {'files': open(zipfile, 'rb')}
        r = requests.post(upload_url, files=files)
        if r.status_code == 200:
            c.insert(data)
            return response + UIMessage('File Uploaded!!')
        else:
            return response + UIMessage('Whoops file upload didn\'t work.')
    except Exception as e:
        return response + UIMessage(str(e))
