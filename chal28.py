#!/usr/bin/env python

#     chal28.py - Implement SHA-1 keyed MAC
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn, sha1, leftrotate, str2int, unknown_key as k

m = 'Vanilla'

def secret_prefix_mac(message, key):
    assert len(key) == 16
    string = hex(sha1(key + message))
    if string[-1] =="L":
        return string[2:-1]
    else:
        return string[2:]

print "Message\t\t\t", secret_prefix_mac(m, k)
print "Tampered message\t", secret_prefix_mac('vanilla', k)
print "Tampered message\t", secret_prefix_mac('Vanilla ', k)
print "Tampered message\t", secret_prefix_mac('Vanilla\x00', k)
print "Tampered message\t", secret_prefix_mac('Vanille', k)
print "Lost key\t\t", secret_prefix_mac(m, 'YELLOW SUBMARINE')
print "Lost key\t\t", secret_prefix_mac(m, 'abcdefghijklmnop')
print "Lost key\t\t", secret_prefix_mac(m, '1234567890123456')
print "Lost key\t\t", secret_prefix_mac(m, '                ')
print "Lost key\t\t", secret_prefix_mac(m, '_______--_______')
print "Lost key\t\t", secret_prefix_mac(m, '\x00' * 16)

#### tests, if any ####
warn("Passed assertions:", __file__)
