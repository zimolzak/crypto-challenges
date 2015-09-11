#!/usr/bin/env python

#     chal32.py - Break a MAC with small timing leak. Multiple
#     replicates of challenge 31.
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from timing_leak import find_mac_url_by_timing, NoIncrement
from cryptopals import warn
import urllib2

base_url = 'http://0.0.0.0:8080/test?file=topsecret&signature='

T = 3.0 # Milliseconds that constitute significant delay.

max_failures = 20
# Number of times to tolerate failure of adding a letter (i.e. false
# stops) before giving up (returning control to the user). Important
# because my algorithm has no sense of a minimum length of a
# string--doesn't assume it will be 40 hexadecimal characters exactly.

backtrack = 1 
# Critical: num of chars to back up upon failure. 1 is ok if you use
# averaging (N_time_meas > 1). 2 is conservative.

N_time_meas = 10
# How many times we repeat (and average) the same exact HTTP request
# at the very lowest level of the algorithm.

# setting T=10, backtrack=1, and N=1 is about equivalent to challenge 31.
#         T=3.0, max_failures=20, backtrack=1, and N=10 will beat 3.5ms delay.

ac = ""
#ac = "5d692a0ec84dc4638f03c16d0dcfa0031688403"
# If the algorithm gives up early (after max_failures loops), you can
# manually set this to your guess for the beginning of the target
# string. Note that if it dies early, it might mean it was guessing
# wrong, so maybe don't copy paste all of the string.

for i in range(max_failures):
    answer = None
    try:
        answer = find_mac_url_by_timing(base_url, T, debug=True, all_chars=ac, N=N_time_meas)
        break
    except NoIncrement as partial_url:
        candidate_str = str(partial_url).replace(base_url, '')
        candidate_str = candidate_str[:-backtrack] 
        if len(candidate_str) > len(ac):
            ac = candidate_str
            print partial_url, "    ?!"
        else:
            print partial_url, "    ??"

if answer:
    print
    print "Hooray!", answer
    print "Page contents:"
    response_obj = urllib2.urlopen(answer)
    n_wins = 0
    for line in response_obj.read().splitlines():
        n_wins += 'winner' in line
        print "    " + line

#### tests
assert n_wins > 0
warn("Passed assertions:", __file__)
