#!/usr/bin/env python

# Part of the sniffMyPackets v2 framework

import magic
from dbconnect import mongo_connect
import time


def check_file(filename):
    try:
        m = magic.open(magic.MAGIC_NONE)
        m.load()
        f = m.file(filename)
        return f
    except Exception as e:
        return str(e)


def error_logging(error, module):
    e = str(error)
    now = time.strftime("%c")
    try:
        # Connect to the database so we can insert the record created below
        x = mongo_connect()
        c = x['ERRORS']
        rec = {'TimeStamp': now, 'Module': module, 'Error Message': error}
        c.insert(rec)
    except:
        pass


