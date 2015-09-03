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
y3 = y4 ^ (y4 >> 18)

y2_r15 = y3 & (2**15 - 1)
y2_ls_t = y2_r15 << 15    # first octet unknown
y2_ls_andc = y2_ls_t & c  # first octet unknown
y2 = y3 ^ y2_ls_andc

y1_r7 = y2 & (2**7 - 1)
y1_ls_s = y1_r7 << 7      # first 9 octets unknown, 14 bit known
y1_ls_andb = y1_ls_s & b  # first 9 octets unknown
y1 = y2 ^ y1_ls_andb

y0 = y1 ^ (y1 >> 11)      # only 3 bit known! 

print hex(y0)



#### tests, if any ####
warn("No errors:", __file__)
