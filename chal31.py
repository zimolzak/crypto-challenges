#!/usr/bin/env python

#     chal31.py - Query a web app and use timing leak to discover
#     valid MAC for any file, without knowing key.
#
#     Theoretical runtime is: 0.050 s/char * 8 (for failed attempts) *
#     (\sum_{i=1}^{n} i) char. This is 5.4667 min when n=40. Obviously
#     O(n^2). In practice it runs 7-8 min on my MacBook Pro.
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

import urllib2
from cryptopals import warn
from timing_leak import find_mac_url_by_timing, NoIncrement

#### Main loop
    
base_url = 'http://0.0.0.0:8080/test?file=confidential&signature='
T = 10 # Milliseconds that constitute significant delay.

answer = None
n_wins = 0
try:
    answer = find_mac_url_by_timing(base_url, T, debug=True)
except NoIncrement as partial_url:
    print "oh well", partial_url

if answer:
    print
    print "Hooray!", answer
    print "Page contents:"
    response_obj = urllib2.urlopen(answer)
    n_wins = 0
    for line in response_obj.read().splitlines():
        n_wins += 'winner' in line
        print "    " + line

assert n_wins > 0
warn("Passed assertions:", __file__)
