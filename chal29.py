#!/usr/bin/env python

#     chal29.py - Break a secret prefix SHA-1 MAC
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn, secret_prefix_mac, unknown_key as k_true
from sha_analysis import sha_padding

m_true = 'Vanilla'
authentic = secret_prefix_mac(m_true, k_true)
print "Message\t\t\t", authentic
print [sha_padding(m_true)]

#### tests, if any ####
warn("Passed assertions:", __file__)
