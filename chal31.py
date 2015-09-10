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
    """Time how many milliseconds between a HTTP request and a 500 error
    status. If no 500 error, then we have guessed right!
    """
    start = time.time()
    try:
        dummy_response = urllib2.urlopen(url)
    except urllib2.HTTPError:
        n = time.time()
        return round(1000 * (n - start), 1)
    else:
        raise SuccessfulBreak(url)

class SuccessfulBreak(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return self.value

def next_char(urlstub, known_chars, tail, threshold):
    """Given a base URL and 0 or more known characters of a value in the
    URL, return probable next character of that value.

    It assumes there is a timing leak due to an early-exit string
    compare on the server side. In other words, it returns the hex
    character that results in a big step-up in server response time
    when that character is appended. threshold determines how many
    milliseconds is "big." urlstub should be like
    'http://foo.com?user=bozo&secret='. known_chars should be like
    'c7a8c58f'. tail is usually one or more padding characters that
    allows the string compare to run into it and exhibit a timing
    difference. If no difference is found, though, then we might be
    done and might want to run it with no tail padding.
    """
    t0 = None
    for hc in ['0', '1', '2', '3', '4', '5', '6', '7',
               '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']:
        attempt = urlstub + known_chars + hc + tail
        t1 = time_url(attempt)
        if t0 == None:
            # We have no comparison so postpone.
            print t1, "....", attempt, "(p)"
            t0 = t1
        elif t1 - t0 > threshold:
            # Found.
            print t1, (t1 - t0), attempt, "*", hc
            return hc
        elif t0 - t1 > threshold:
            # Found after postponement (note reversed subtraction).
            print t1, (t1 - t0), attempt, "^"
            return hex(int(hc, 16) - 1)[2] 
        else:
            # Not found.
            print t1, (t1 - t0), attempt
            t0 = t1

def next_char_or_success(urlstub, known_chars, threshold):
    """Given a base URL and known characters, return probable next
    character, and if none is found, try to guess complete correct
    URL.
    """
    nc = next_char(urlstub, known_chars, 'z', threshold)
    if nc:
        return nc
    else:
        pass
    # Assume that the next statement (without "tail" padding) will
    # find the correct URL and thus throw an exception.
    nc = next_char(urlstub, known_chars, '', threshold)
    assert 0

def find_mac_url_by_timing(base_url, T):
    all_chars = ""
    while(1):
        try:
            all_chars += next_char_or_success(base_url, all_chars, T)
        except SuccessfulBreak as url_result:
            return str(url_result)

#### Main loop
    
base_url = 'http://0.0.0.0:8080/test?file=terminator&signature='
T = 20 # Milliseconds that constitute significant delay.
answer = find_mac_url_by_timing(base_url, T)

print
print "Hooray!", answer
print "Page contents:"
response_obj = urllib2.urlopen(answer)
n_wins = 0
for line in response_obj.read().splitlines():
    n_wins += 'winner' in line
    print "    " + line

#### tests, if any ####
assert n_wins > 0
warn("Passed assertions:", __file__)
