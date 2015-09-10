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
import time
from cryptopals import warn

# http://0.0.0.0:8080/test?file=bad&signature=605414df80961f70aff091df8e38d4cac526df99

stubs = ['http://0.0.0.0:8080/test?file=bad&signature=',
         'http://0.0.0.0:8080/test?file=bad&signature=6',
         'http://0.0.0.0:8080/test?file=bad&signature=b',
         'http://0.0.0.0:8080/test?file=bad&signature=a0',
         'http://0.0.0.0:8080/test?file=bad&signature=60',
         'http://0.0.0.0:8080/test?file=bad&signature=b0'
]

def time_stub(url):
    start = time.time()
    try:
        response_obj = urllib2.urlopen(url)
    except urllib2.HTTPError as err:
        n = time.time()
        return round(1000 * (n - start), 1)
    else:
        return url

for x in stubs:
    print time_stub(x)

hexchars = ['0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']

class SuccessfulBreak(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return self.value

def next_char(urlstub, found_chars):
    ltime = None
    for hc in hexchars:
        if found_chars == "":
            stub = urlstub + found_chars + hc + 'z'
        else:
            stub = urlstub + found_chars + hc + 'z'
        ntime = time_stub(stub)
        if type(ntime) == type(str()):
            raise SuccessfulBreak(ntime)
        elif ltime == None:
            print ntime, stub, "(p)"
            ltime = ntime
        elif ntime - ltime > 20:
            print ntime, stub, "*", hc
            return hc
        elif ntime - ltime < -20:
            print ntime, stub, "^"
            return hex(int(hc, 16)-1)[2]
        else:
            print ntime, (ntime-ltime), stub
            ltime = ntime
    # only reaches here if all look equal. Try without 'z'
    ltime = None
    for hc in hexchars:
        stub = urlstub + found_chars + hc
        ntime = time_stub(stub)
        if type(ntime) == type(str()):
            raise SuccessfulBreak(ntime)
        elif ltime == None:
            print ntime, stub, "(p)"
            ltime = ntime
        elif ntime - ltime > 20:
            print ntime, stub, "*", hc
            return hc
        elif ntime - ltime < -20:
            print ntime, stub, "^"
            return hex(int(hc, 16)-1)[2]
        else:
            print ntime, (ntime-ltime), stub
            ltime = ntime

#all_chars = "605414df80961f70aff091df8e38d4cac526df9"
all_chars = ""
final = ""
while(1):
    try:
        all_chars += next_char('http://0.0.0.0:8080/test?file=noclist&signature=',
                               all_chars)
    except SuccessfulBreak as b:
        print "Hooray!", b
        final = str(b)
        break

print final
response_obj = urllib2.urlopen(final)
winner = 0
for line in response_obj.read().splitlines():
    winner += 'winner' in line
    print "    " + line

#### tests, if any ####
assert winner
warn("Passed assertions:", __file__)
