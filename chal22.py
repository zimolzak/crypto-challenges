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

#time.sleep(random.randint(40,1000))
#r = MTRNG(int(time.time()))
#time.sleep(random.randint(40,1000))
#print r.extract_number()

target_num = 1324987356
for s in range(1441204448, 1441205339):
    m = MTRNG(s)
    if m.extract_number() == target_num:
        print "Seed used was:", s
        print "In other words,", time.ctime(s)
        break

#### tests, if any ####
warn("No errors:", __file__)
