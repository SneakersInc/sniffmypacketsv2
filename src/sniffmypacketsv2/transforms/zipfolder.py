#!/usr/bin/env python

import os
import zipfile
from common.entities import Folder, ZipFile
from canari.maltego.message import UIMessage, Field
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
    label='Zip Folder',
    description='Zip the working directory folder',
    uuids=['sniffMyPacketsv2.v2.folder_2_zip'],
    inputs=[('[SmP] - Sessions', Folder)],
    debug=True
)
def dotransform(request, response):

    folder = request.value
    pcap_id = request.fields['sessionid']
    save_file = '%s/%s.zip' % (folder, pcap_id)

    try:
        # Zip the files in the specified folder
        def zipdir(path, zip):
            for root, dirs, files in os.walk(path):
                for file in files:
                    zip.write(os.path.join(root, file))

        myzip = zipfile.ZipFile(save_file, 'w')
        zipdir(folder, myzip)
        myzip.close()

    except Exception as e:
        return response + UIMessage(str(e))

    e = ZipFile(save_file)
    e += Field('folder', folder, displayname='Folder')
    e += Field('sessionid', pcap_id, displayname='Session ID')
    response += e
    return response
