#!/usr/bin/env python

#     chal32.py - Break a MAC with small timing leak. Multiple
#     replicates of challenge 31.
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from timing_leak import find_mac_url_by_timing, NoIncrement
import urllib2

base_url = 'http://0.0.0.0:8080/test?file=xfiles&signature='
T = 4.7 # Milliseconds that constitute significant delay.
replicates = 10

#ac = "98777ae85b1044e762d0057ee53e2d20d2c65cc"
ac = "98777"
for i in range(replicates):
    answer = None
    try:
        answer = find_mac_url_by_timing(base_url, T, debug=False, all_chars=ac)
        break
    except NoIncrement as partial_url:
        print partial_url, "    ??"
        candidate_str = str(partial_url).replace(base_url, '')
        candidate_str = candidate_str[:-2] # Conservative. Neg 1 prob OK.
        if len(candidate_str) > len(ac):
            ac = candidate_str

if answer:
    print
    print "Hooray!", answer
    print "Page contents:"
    response_obj = urllib2.urlopen(answer)
    for line in response_obj.read().splitlines():
        print "    " + line
