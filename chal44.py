#!/usr/bin/env python

#     chal44.py - DSA key recovery from repeated nonce
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
from rsa import invmod
from dsa import p, q, g, find_private_key

for line in open('44.txt', 'r').read().splitlines():
    print line


#### tests ####
warn("Passed assertions:", __file__)
