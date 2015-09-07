#!/usr/bin/env python

#     chal28.py - Implement SHA-1 keyed MAC
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn, sha1, leftrotate, str2int, unknown_key as k_true

m_true = 'Vanilla'

def secret_prefix_mac(message, key):
    assert len(key) == 16
    string = hex(sha1(key + message))
    if string[-1] =="L":
        return string[2:-1]
    else:
        return string[2:]

m_tamper = ['vanilla', 'Vanilla ', 'Vanilla\x00', 'Vanille']
lost_key = ['YELLOW SUBMARINE',
            'abcdefghijklmnop',
            '1234567890123456',
            '                ',
            '_______--_______',
            '\x00' * 16]

authentic = secret_prefix_mac(m_true, k_true)
print "Message\t\t\t", authentic

#### tests, if any ####
for m in m_tamper:
    mac = secret_prefix_mac(m, k_true)
    print "Tampered message\t", mac
    assert mac != authentic

for l in lost_key:
    mac = secret_prefix_mac(m_true, l)
    print "Lost key\t\t", mac
    assert mac != authentic

warn("Passed assertions:", __file__)
