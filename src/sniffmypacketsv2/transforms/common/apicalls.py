#!/usr/bin/env python

# Part of the sniffMyPackets v2 Framework

import time
import requests
import canari.config

vtapi = canari.config.config['api/vt'].strip('\'')


def vt_lookup_file(md5hash):
    time.sleep(15)
    base_url = 'https://www.virustotal.com/vtapi/v2/file/report'
    payload = {'resource': md5hash, 'apikey': vtapi}
    try:
        r = requests.post(base_url, data=payload)
        if r.status_code != 200:
            pass
        j = r.json()
        if j['response_code'] == 0:
            pass
        else:
            return j
    except Exception as e:
        return str(e)


def vt_lookup_url(url):
    base_url = 'http://www.virustotal.com/vtapi/v2/url/report'
    payload = {'resource': url, 'apikey': vtapi}
    try:
        r = requests.post(base_url, data=payload)
        if r.status_code != 200:
            pass
        j = r.json()
        if j['response_code'] == 0:
            pass
        else:
            return j['permalink']
    except Exception as e:
        return str(e)


def vt_lookup_ip(ipaddr):
    base_url = 'http://www.virustotal.com/vtapi/v2/ip-address/report'
    payload = {'ip': ipaddr, 'apikey': vtapi}
    try:
        r = requests.get(base_url, data=payload)
        if r.status_code != 200:
            pass
        j = r.json()
        if j['response_code'] == 0:
            pass
        else:
            return j
    except Exception as e:
        return str(e)


def vt_lookup_domain(domain):
    base_url = 'http://www.virustotal.com/vtapi/v2/domain/report'
    payload = {'domain': domain, 'apikey': vtapi}
    try:
        r = requests.get(base_url, data=payload)
        if r.status_code != 200:
            pass
        j = r.json()
        if j['response_code'] == 0:
            pass
        else:
            return j
    except Exception as e:
        return str(e)