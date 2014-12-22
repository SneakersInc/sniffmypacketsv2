#!/usr/bin/env python

import os
import email
import mimetypes
from common.dbconnect import mongo_connect
from common.entities import Artifact, EmailAttachment
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
    label='Extract Email Attachments',
    description='Extract Email attachments from an artifact',
    uuids=['sniffMyPacketsv2.v2.artifact_2_email_attachment'],
    inputs=[('[SmP] - Email', Artifact)],
    debug=True
)
def dotransform(request, response):

    f = request.value
    d = mongo_connect()
    c = d['ARTIFACTS']
    folder = []
    # Check the pcap file doesn't exist in the database already (based on MD5 hash)
    try:
        s = d.ARTIFACTS.find({"File Name": f}).count()
        if s > 0:
            r = d.ARTIFACTS.find({"File Name": f}, {"Path": 1, "_id": 0})
            for i in r:
                folder = i['Path']
                # print folder
        else:
            return response + UIMessage('File not found!!')
    except Exception as e:
        return response + UIMessage(str(e))
    # print folder
    msgdata = []
    lookfor = 'DATA'
    file = '%s/%s' % (folder, f)

    # split the original file into two parts, message and header and save as lists
    with open(file, mode='r') as msgfile:
        reader = msgfile.read()
        for i, part in enumerate(reader.split(lookfor)):
            if i == 1:
                msgdata.append(part.strip())

    for item in msgdata:
        newfolder = '%s/emails' % folder
        if not os.path.exists(newfolder):
            os.makedirs(newfolder)
            filename = folder + '/' + 'msgdata.msg'
            fb = open(filename, 'w')
            fb.write('%s\n' % item)
            fb.close()

            fp = open(filename)
            msg = email.message_from_file(fp)
            fp.close()

            counter = 1
            for part in msg.walk():
                if part.get_content_maintype() == 'multipart':
                    continue
                filename = part.get_filename()
                if not filename:
                    ext = mimetypes.guess_extension(part.get_content_type())
                    if not ext:
                        ext = '.bin'
                    filename = 'part-%03d%s' % (counter, ext)
                counter += 1

                savefile = newfolder + '/' + filename
                fp = open(savefile, 'wb')
                fp.write(part.get_payload(decode=True))
                fp.close()

                # Create the Maltego entity
                e = EmailAttachment(savefile)
                response += e
            return response