#!/usr/bin/env python

# Part of sniffMyPackets framework.
# Hashing modules to cut down on code changes.

import hashlib


def md5_for_file(path):
    try:
        f = open(path, 'rb')
        md5hash = hashlib.md5(f.read()).hexdigest()
        return md5hash
    except Exception as e:
        return str(e)


def sha1_for_file(path):
    try:
        f = open(path, 'rb')
        sha1hash = hashlib.sha1(f.read()).hexdigest()
        return sha1hash
    except Exception as e:
        return str(e)


def sha256_for_file(path):
    try:
        f = open(path, 'rb')
        sha256hash = hashlib.sha256(f.read()).hexdigest()
        return sha256hash
    except Exception as e:
        return str(e)

