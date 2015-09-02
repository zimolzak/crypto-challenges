#!/usr/bin/env python

#     chal21.py - Implement MT19937
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
from myrand import MTRNG

r = MTRNG(12436)
print r.extract_number()
print r.extract_number()
print r.extract_number()
print r.extract_number()
print r.extract_number()
print r.extract_number()
print r.extract_number()
print r.extract_number()

#### tests, if any ####
warn("No errors:", __file__)
