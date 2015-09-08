#!/usr/bin/env python

#     chal29.py - Break a secret prefix SHA-1 MAC
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import (warn, secret_prefix_mac, sha1, sha_padding,
                        unknown_key as k_true)
from sha_analysis import restart_sha
import math

def i2h(n):
    string = hex(n)
    if string[-1] =="L":
        return string[2:-1]
    else:
        return string[2:]

m = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
auth_code = sha1(k_true + m)
print "Message", m
print "Auth code for M:       ", i2h(auth_code)
print "Story checks out?      ", auth_code == sha1(k_true + m) 
print

#### Mallory starts here

adm = ";admin=true"
keylen = 16 #just a guess
KOG_len = int(math.ceil((keylen + len(m)) / 64.0)) * 64
  # Len of key+original+glue
print "kog len", KOG_len
glue = sha_padding(("A" * keylen) +  m, 0)
nm = m + glue + adm
#extra_len = len(m + glue)
nac = restart_sha(auth_code, adm, KOG_len)
print "New Message", [nm]
print "Guess auth code for NM:", i2h(nac)
i_am_a_winner = (nac == sha1(k_true + nm))
print "Story checks out?      ", i_am_a_winner
print

print "Cheat                  ", [sha_padding(k_true + m, 0)]
print "Cheat                  ", i2h(sha1(k_true + nm))
nmcheat = m + sha_padding(k_true + m, 0) + adm
print "Are we guessing glue padding right?", nmcheat == nm

#### tests, if any ####
assert i_am_a_winner
warn("Passed assertions:", __file__)
