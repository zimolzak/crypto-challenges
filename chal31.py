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

def time_url(url):
    start = time.time()
    try:
        response_obj = urllib2.urlopen(url)
    except urllib2.HTTPError as err:
        n = time.time()
        return round(1000 * (n - start), 1)
    else:
        return url

hexchars = ['0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']

class SuccessfulBreak(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return self.value

def next_char(urlstub, known_chars):
    """Given a base URL and 0 or more known characters of a value in the
    URL, return probable next character of that value.

    It assumes there is a timing leak due to an early-exit string
    compare on the server side. In other words, it returns the hex
    character that results in a big step-up in server response time
    when that character is appended. urlstub should be like
    'http://foo.com?user=bozo&secret='. known_chars should be like
    'c7a8c58f'.
    """
    ltime = None
    for hc in hexchars:
        attempt = urlstub + known_chars + hc + 'z'
        ntime = time_url(attempt)
        if type(ntime) == type(str()):
            raise SuccessfulBreak(ntime)
        elif ltime == None:
            print ntime, attempt, "(p)"
            ltime = ntime
        elif ntime - ltime > 20:
            print ntime, attempt, "*", hc
            return hc
        elif ntime - ltime < -20:
            print ntime, attempt, "^"
            return hex(int(hc, 16)-1)[2]
        else:
            print ntime, (ntime-ltime), attempt
            ltime = ntime
    # Only reaches here if all look equal. Thus, will try without 'z'
    ltime = None
    for hc in hexchars:
        attempt = urlstub + known_chars + hc
        ntime = time_url(attempt)
        if type(ntime) == type(str()):
            raise SuccessfulBreak(ntime)
        elif ltime == None:
            print ntime, attempt, "(p)"
            ltime = ntime
        elif ntime - ltime > 20:
            print ntime, attempt, "*", hc
            return hc
        elif ntime - ltime < -20:
            print ntime, attempt, "^"
            return hex(int(hc, 16)-1)[2]
        else:
            print ntime, (ntime-ltime), attempt
            ltime = ntime

all_chars = ""
base_url = 'http://0.0.0.0:8080/test?file=noclist&signature='
while(1):
    try:
        all_chars += next_char(base_url, all_chars)
    except SuccessfulBreak as url_result:
        break

print "Hooray!", url_result
response_obj = urllib2.urlopen(url_result)
winner = 0
for line in response_obj.read().splitlines():
    winner += 'winner' in line
    print "    " + line

#### tests, if any ####
assert winner
warn("Passed assertions:", __file__)
