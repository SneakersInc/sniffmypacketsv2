#!/usr/bin/env python

# Part of the sniffMyPackets v2 framework

import magic


def check_file(filename):
    try:
        m = magic.open(magic.MAGIC_NONE)
        m.load()
        f = m.file(filename)
        return f
    except Exception as e:
        return str(e)