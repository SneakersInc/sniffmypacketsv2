#!/usr/bin/env python

# Part of the sniffMyPackets v2 framework

import sqlite3 as lite

#
# def cipher_list(ctype):
#     # Connect to the local aux database
#     try:
#         con = lite.connect('aux.db')
#         with con:
#             cur = con.cursor()
#             cur.execute('SELECT * FROM ciphers WHERE ')