#!/usr/bin/env python

#     chal29.py - Break a secret prefix SHA-1 MAC
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import (warn, secret_prefix_mac, sha1, sha_padding,
                        unknown_key as k_true)

m = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"

authentic = secret_prefix_mac(m, k_true)
print "Message\t\t\t", authentic
print "Padding:"
print [sha_padding(m)]
print "Unkeyed", hex(sha1(m))
print "Unkeyed  ", secret_prefix_mac(m, "")


#### tests, if any ####
warn("Passed assertions:", __file__)
