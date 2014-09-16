#!/usr/bin/env python

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
    print "Could not connect to MongoDB: %s" % e
  else:
    return db



