#!/usr/bin/env python

#     chal23.py - Clone MT19937
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
from myrand import MTRNG, c, b

m = MTRNG(67812)
#print m.extract_number()

y4 = 0xe016575d

#### begin "untemper" ####

y3 = y4 ^ (y4 >> 18)

y2 = y3 & (2**15 - 1)     # 15 bit
y2_ls = y2 << 15          # 30 bit
y2_ls_andc = y2_ls & c
y2 = y3 ^ y2_ls_andc
y2_ls = y2 << 15          # 32 bit (45)
y2_ls_andc = y2_ls & c
y2 = y3 ^ y2_ls_andc

y1 = y2 & (2**7 - 1)      # 7 bit
y1_ls = y1 << 7           # 14 bit
y1_ls_andb = y1_ls & b
y1 = y2 ^ y1_ls_andb
y1_ls = y1 << 7           # 21 bit
y1_ls_andb = y1_ls & b
y1 = y2 ^ y1_ls_andb
y1_ls = y1 << 7           # 28 bit
y1_ls_andb = y1_ls & b
y1 = y2 ^ y1_ls_andb
y1_ls = y1 << 7           # 32 bit (35)
y1_ls_andb = y1_ls & b
y1 = y2 ^ y1_ls_andb

y0 = y1                  # 11 bit (highest bits)
y0 = y1 ^ (y0 >> 11)     # 22 bit
y0 = y1 ^ (y0 >> 11)     # 32 bit (33)

print "y0", hex(y0)

#### tests, if any ####
assert y0 == 0xdeadbeef
warn("Passed assertions:", __file__)
