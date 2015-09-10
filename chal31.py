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

# 'bad&signature=605414df80961f70aff091df8e38d4cac526df99',

stubs = ['bad&signature=',
         'bad&signature=6',
         'bad&signature=b',
         'bad&signature=a0',
         'bad&signature=60',
         'bad&signature=b0'
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

class SuccessfulBreak(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return self.value

def next_char(urlstub, found_chars):
    ltime = None
    for hc in hexchars:
        if found_chars == "":
            stub = 'bad&signature=' + found_chars + hc + 'z'
        else:
            stub = 'bad&signature=' + found_chars + hc + 'z'
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
        stub = 'bad&signature=' + found_chars + hc
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

all_chars = ""
final = ""
while(1):
    try:
        all_chars += next_char('http://0.0.0.0:8080/test?file=bad&signature=',
                               all_chars)
    except SuccessfulBreak as b:
        print "Hooray!", b
        final = str(b)
        break

url = 'http://0.0.0.0:8080/test?file=' + final
print url
response_obj = urllib2.urlopen(url)
winner = 0
for line in response_obj.read().splitlines():
    winner += 'winner' in line
    print "    " + line

#### tests, if any ####
assert winner
warn("Passed assertions:", __file__)
