#!/usr/bin/env python

#     chal45.py - DSA parameter injection
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
from rsa import invmod
from dsa import p, q, sign, verify, g
import random

m = ["Hello, world", "Goodbye, world"]
x = random.randint(1, q) # private key

def print_long(n):
    s = str(n)
    if len(s) > 50:
        return s[:50] + " ..."
    else:
        return s

def tamper(m, g):
    y = pow(g, x, p)
    [r, s] = sign(m, g, p, q, x)
    print "m        ", m
    print "g        ", print_long(g)
    print "x (shh!) ", x
    print "y        ", print_long(y)
    print "sig      ", r
    print "         ", s
    return [r,s,y]

for message in m:
    [r,s,y] = tamper(message, g)
    answer = verify(message, g, p, q, r, s, y)
    print "verifies?", answer
    print

#### tests ####
warn("Passed assertions:", __file__)
