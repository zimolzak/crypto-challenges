#!/usr/bin/env python

#     chal31.py - Query a web app and use timing leak to discover
#     valid MAC for any file, without knowing key.
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

import urllib2
import time
from cryptopals import warn

stubs = ['bad&signature=605414df80961f70aff091df8e38d4cac526df99',
         'bad&signature=',
         'bad&signature=6',
         'bad&signature=b',
         'bad&signature=a0',
         'bad&signature=60',
         'bad&signature=b0',
]

def time_stub(s):
    url = 'http://0.0.0.0:8080/test?file=' + s
    start = time.time()
    try:
        response_obj = urllib2.urlopen(url)
    except urllib2.HTTPError as err:
        n = time.time()
        return round(1000 * (n - start), 1)
    else:
        return s

for x in stubs:
    print time_stub(x)

hexchars = ['0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']

ltime = 9999
for hc in hexchars:
    stub = 'bad&signature=' + hc + '0'
    ntime = time_stub(stub)
    if ntime - ltime > 20:
        print ntime, stub
        break
    else:
        print ntime, stub
        ltime = ntime

#### tests, if any ####
warn("Passed assertions:", __file__)
