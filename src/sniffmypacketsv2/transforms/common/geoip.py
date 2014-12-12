#!/usr/bin/env python

# Part of sniffMyPackets framework.
# GeoIP Lookup modules to cut down on code changes.

import pygeoip
from canari.config import config


def lookup_geo(ip):
    try:
        homelat = config['geoip/homelat'].strip('\'')
        homelng = config['geoip/homelng'].strip('\'')
        db = config['geoip/db'].strip('\'')
        try:
            gi = pygeoip.GeoIP(db)
        except Exception as e:
            return str(e)
        rec = gi.record_by_addr(ip)
        if rec is not None:
            return rec
        else:
            geo = {'latitude': homelat, 'longitude': homelng, 'country_name': 'N/A'}
            return geo
    except Exception as e:
        return str(e)
