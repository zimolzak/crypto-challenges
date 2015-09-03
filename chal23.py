#!/usr/bin/env python

#     chal23.py - Clone MT19937
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
from myrand import MTRNG, c, b, u, s, t, l

m = MTRNG(67812)
#print m.extract_number()

def untemper_right(input, k):
    output = input
    bits = k
    while bits < 32:
        output = input ^ (output >> k)
        bits += k
    return output

def untemper_left(input, k, mask):
    output = input
    bits = k
    while bits < 32:
        output = input ^ ((output << k) & mask)
        bits += k
    return output

def untemper(y4):
    y3 = untemper_right(y4, l)
    y2 = untemper_left(y3, t, c)
    y1 = untemper_left(y2, s, b)
    return untemper_right(y1, u)

answer = untemper(0xe016575d)
print hex(answer)

#### tests, if any ####
assert answer == 0xdeadbeef
warn("Passed assertions:", __file__)
