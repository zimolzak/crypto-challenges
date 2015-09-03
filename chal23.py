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

def untemper(y4):

    y3 = y4
    bits = l
    while bits < 32:
        y3 = y4 ^ (y3 >> l)
        bits += l

    y2 = y3
    bits = t
    while bits < 32:
        y2_ls = y2 << t
        y2_ls_andc = y2_ls & c
        y2 = y3 ^ y2_ls_andc
        bits += t

    y1 = y2
    bits = s
    while bits < 32:
        y1_ls = y1 << s
        y1_ls_andb = y1_ls & b
        y1 = y2 ^ y1_ls_andb
        bits += s

    y0 = y1
    bits = u
    while bits < 32:
        y0 = y1 ^ (y0 >> u)
        bits += u

    return y0

answer = untemper(0xe016575d)
print hex(answer)

#### tests, if any ####
assert answer == 0xdeadbeef
warn("Passed assertions:", __file__)
