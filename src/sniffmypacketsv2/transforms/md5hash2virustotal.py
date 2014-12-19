#!/usr/bin/env python

from common.apicalls import vt_lookup_file
from common.dbconnect import mongo_connect
from common.entities import Artifact, VirusTotal
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
    label='Query VirusTotal',
    description='Lookup MD5 hash on virustotal',
    uuids=['sniffMyPacketsv2.v2.md5hash_2_virustotal'],
    inputs=[('[SmP] - Artifacts', Artifact)],
    debug=True
)
def dotransform(request, response):
    filename = request.value
    md5hash = request.fields['sniffmypacketsv2.fhash']

    # Connect to the database so we can insert the record created below
    x = mongo_connect()
    c = x['MALWARE']

    v = vt_lookup_file(md5hash)

    if v is not None:
        link = v['permalink']
        scan = v['scan_date']
    else:
        return response + UIMessage('No record found in VirusTotal')

    s = x.ARTIFACTS.find({'MD5 HASH': md5hash}, {"PCAP ID": 1, "_id": 0})
    pcap_id = ''
    for m in s:
        pcap_id = m['PCAP ID']

    data = {'PCAP ID': pcap_id, 'File Name': filename, 'Permalink': link, 'Scan Date': scan, 'MD5 Hash': md5hash}

    t = x.MALWARE.find({'MD5 Hash': md5hash}).count()
    if t > 0:
        pass
    else:
        c.insert(data)

    e = VirusTotal(link)
    response += e
    return response
