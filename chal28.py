#!/usr/bin/env python

#     chal28.py - Implement SHA-1 keyed MAC
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn, sha1, leftrotate, str2int
from Crypto.Hash import SHA

h = SHA.new()
h.update('Vanilla')
print "builtin says", h.hexdigest()

print sha1('Vanilla')

#### tests, if any ####
warn("Passed assertions:", __file__)
