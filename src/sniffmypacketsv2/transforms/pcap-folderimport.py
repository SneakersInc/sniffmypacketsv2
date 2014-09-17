#!/usr/bin/env python

import os
import glob
from common.entities import Folder, pcapFile
# from canari.maltego.utils import debug, progress
from canari.framework import configure #, superuser

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

#@superuser
@configure(
    label='Import PCAP\'s from Folder',
    description='Import pcaps from specified folder',
    uuids=[ 'sniffmypacketsv2.v2.import_pcaps_folder' ],
    inputs=[ ( '[SmP] - Misc', Folder ) ],
    debug=True
)
def dotransform(request, response, config):
  e = ['.cap', '.pcap']
  files = []
  for i in e:
    files = glob.glob(request.value + '/*' + i)
  for x in files:
    e = pcapFile(x)
    response += e
  return response
