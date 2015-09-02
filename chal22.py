#!/usr/bin/env python

#     chal22.py - MT19937 seed
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
from myrand import MTRNG
import time
import random

time.sleep(random.randint(40,1000))
r = MTRNG(int(time.time()))
time.sleep(random.randint(40,1000))
target_num = r.extract_number()

found_seed = 0
print "Received target of:", target_num
for s in range(1441224144, int(time.time()) + 60 ):
    m = MTRNG(s)
    if m.extract_number() == target_num:
        found_seed = s
        print "Seed used was:", s
        print "In other words,", time.ctime(s)
        break

#### tests, if any ####
assert(found_seed > 1441224144)
warn("Passed assertions:", __file__)
