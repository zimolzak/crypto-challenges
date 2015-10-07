#!/usr/bin/env python

#     chal45.py - DSA parameter injection
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
from rsa import invmod
from dsa import p, q, sign
import random

g = p # uh oh
m_list = ["Hello, world", "Goodbye, world"]
x = random.randint(1, q) # private key

for m in m_list:
    print sign(m, g, p, q, x)

#### tests ####
warn("Passed assertions:", __file__)
