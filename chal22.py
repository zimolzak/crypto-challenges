#!/usr/bin/env python

#     chal22.py - MT19937 seed
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
from myrand import MTRNG, find_time_seed
import time
import random

#### Generate a number from RNG seeded with time

time.sleep(random.randint(7,15)) # 40,1000 is more fun though
r = MTRNG(int(time.time()))
time.sleep(random.randint(7,15))
target_num = r.extract_number()

#### Reverse engineer the seed

print "Received target of:", target_num

found_seed = find_time_seed(target_num, int(time.time()))

print "Seed used was:", found_seed
print "In other words,", time.ctime(found_seed)

#### tests, if any ####
assert(found_seed > 1441224144)
warn("Passed assertions:", __file__)
