#!/usr/bin/env python

# Part of the sniffMyPackets v2 framework

from canari.config import config
import pymongo


def mongo_connect():
    dbs = config['mongodb/dbs'].strip('\'')
    server = config['mongodb/server'].strip('\'')
    port = config['mongodb/port']
    username = config['mongodb/username'].strip('\'')
    password = config['mongodb/username'].strip('\'')

    try:
        connection = pymongo.MongoClient(server, port)
        db = connection[dbs]
    except pymongo.errors.ConnectionFailure, e:
        return "Could not connect to MongoDB: %s" % e
    else:
        return db


def find_session(md5hash):
    x = mongo_connect()
    # Get the PCAP ID for the pcap file
    try:
        s = x.INDEX.find({"MD5 Hash": md5hash}).count()
        if s == 0:
            t = x.STREAMS.find({"MD5 Hash": md5hash}).count()
            if t > 0:
                r = x.STREAMS.find_one({"MD5 Hash": md5hash}, {"PCAP ID": 1, "Stream ID": 1, "Folder": 1,  "_id": 0})
                for i in r:
                    pcap_id = i['PCAP ID']
                    session_id = i['Stream ID']
                    folder = i['Folder']
                return pcap_id, session_id, folder

            else:
                return 'No PCAP ID, you need to index the pcap file'
        if s > 0:
            r = x.INDEX.find({"MD5 Hash": md5hash}, {"PCAP ID": 1, "Working Directory": 1, "_id": 0})
            for i in r:
                pcap_id = i['PCAP ID']
                session_id = i['PCAP ID']
                folder = i['Working Directory']
            return pcap_id, session_id, folder
    except Exception as e:
        return str(e)



