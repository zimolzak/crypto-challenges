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

def modexp_slow(b, e, m):
    c = 1
    ep = 0
    while ep < e:
        ep += 1
        c = (b * c) % m
    return c

def modexp(b, e, m):
    c = 1
    b = b % m
    while e > 0:
        if e % 2 == 1:
            c = (c * b) % m
        e = e >> 1
        b = (b * b) % m
    return c

a = random.randint(0,36)
A = (g ** a) % p
print g ** a
print A, "?=", modexp(g, a, p), "test of modexp"
assert A == modexp(g, a, p)

b = random.randint(0,36)
B = (g ** b) % p
print g ** b
print B, "?=", modexp(g, b, p), "test of modexp"
assert B == modexp(g, b, p)

s = (B ** a) % p
s2 = (A ** b) % p
print s, "?=", s2, "test of session keys"
assert s == s2

pbig = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

gbig = 2
abig = random.randint(0, pbig - 1)
print type(pbig)
print "ok"

print modexp(gbig, abig, pbig)

#### tests
warn("Passed assertions:", __file__)
