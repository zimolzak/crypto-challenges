#!/usr/bin/env python

#     chal33.py - Implement Diffie-Hellman
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
import random

p = 37
g = 5

def modexp(b, e, m):
    c = 1
    b = b % m
    while e > 0:
        if e % 2 == 1:
            c = (c * b) % m
        e = e >> 1
        b = (b * b) % m
    return c

def get_pubkey_exp(p_mod, g_base):
    a_exp = random.randint(0, p_mod - 1)
    return [modexp(g_base, a_exp, p_mod), a_exp]

[A, a] = get_pubkey_exp(p, g)
[B, b] = get_pubkey_exp(p, g)

s1 = modexp(B, a, p)
s2 = modexp(A, b, p)

print s1, "?=", s2, "(test of little session key equality)"

####

p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

g = 2

[A, a] = get_pubkey_exp(p, g)
[B, b] = get_pubkey_exp(p, g)

s1_big = modexp(B, a, p)
s2_big = modexp(A, b, p)

print "Generated two big session keys of", s1_big.bit_length(), \
    "and", s2_big.bit_length(), "bits."

#### tests
for i in range(1,38):
    for j in range(1,38):
        for k in range(1,38):
            assert (i ** j) % k == modexp(i, j, k)
assert s1 == s2
assert s1_big == s2_big
warn("Passed assertions:", __file__)
