#!/usr/bin/env python

#     chal33.py - Implement Diffie-Hellman
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
from diffie_hellman import get_pubkey_exp, p, g, modexp

p1 = 37
g1 = 5

[A, a] = get_pubkey_exp(p1, g1)
[B, b] = get_pubkey_exp(p1, g1)

s1 = modexp(B, a, p1)
s2 = modexp(A, b, p1)

print s1, "?=", s2, "(test of little session key equality)"

####

[A, a] = get_pubkey_exp(p, g)
[B, b] = get_pubkey_exp(p, g)

s1_big = modexp(B, a, p)
s2_big = modexp(A, b, p)

print "Generated two big session keys of", s1_big.bit_length(), \
    "and", s2_big.bit_length(), "bits."

#### tests
assert s1 == s2
assert s1_big == s2_big
warn("Passed assertions:", __file__)
