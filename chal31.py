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

stubs = ['bad&signature=605414df80961f70aff091df8e38d4cac526df98',
         'bad&signature=605414df80961f70aff091df8e38d4cac526df99',
         'bad&signature=derp',
         'bad&signature=derp',
         'bad&signature=derp',
         'bad&signature=605414df80961f70aff091df8e38d4cac526df98',
         'bad&signature=605414df80961f70aff091df8e38d4cac526df99',
         'bad&signature=605414df80961f70aff091df8e38d4cac526df9z',
         'bad&signature=605414df80961f70aff091df8e38d4cac526dfzz',
         'bad&signature=605414df80961f70aff091df8e38d4cac526dzzz',
         'bad&signature=605414df80961f70aff091df8e38d4cac526zzzz',
         'bad&signature=605414df80961f70aff091df8e38d4cac52zzzzz',
]

for s in stubs:
    url = 'http://0.0.0.0:8080/test?file=' + s
    start = time.time()
    try:
        response_obj = urllib2.urlopen(url)
    except urllib2.HTTPError as err:
        n = time.time()
        print "Error after", round(1000 * (n - start), 1), "ms"
    else:
        n = time.time()
        print "Success after", round(1000 * (n - start), 1), "ms"

#### tests, if any ####
warn("Passed assertions:", __file__)
