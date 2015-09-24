#!/usr/bin/env python

#     chal39.py - Implement RSA
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
import random
import gensafeprime
from math import log, ceil

def extended_gcd(a, b):
    s = 0;    old_s = 1
    t = 1;    old_t = 0
    r = b;    old_r = a
    while r != 0:
        quotient = old_r / r
        (old_r, r) = (r, old_r - quotient * r)
        (old_s, s) = (s, old_s - quotient * s)
        (old_t, t) = (t, old_t - quotient * t)
    return {"B":[old_s, old_t], "G":old_r, "Q":[t, s]}

def invmod(a, m):
    D = extended_gcd(a,m)
    if D['G'] != 1:
        raise Exception("a and m are not coprime. "
                        + str(a) + " " + str(m) + " " + str(D['G']))
    ans = D['B'][0]
    if ans < 0:
        ans += m
    return ans

def keypair(bits):
    p = gensafeprime.generate(bits)
    q = gensafeprime.generate(bits)
    n = p * q
    et = (p-1) * (q-1)
    e = 3
    d = invmod(e, et)
    Public = [e, n]
    Private = [d, n]
    return [Public, Private]

def crypt(message, key):
    return pow(message, key[0], key[1])

def hexord(char):
    return hex(ord(char))[2:]

def s2i(string):
    """This is the cheesiest possible way I can think to do this."""
    return int('0x' + ''.join((map(hexord, string))), 16)

def i2s(integer):
    out = ""
    while integer:
        out += chr(integer & 0xff)
        integer = integer >> 8
    f = list(out)
    f.reverse()
    return ''.join(f)

hello = 'Hello, world! This is a message from me to you! I am typing this on a certain type of computer, and I wonder how many bits I will need.'

integer = s2i(hello)
bits = len(hello) * 8 / 2
print bits
U, R = keypair(bits)
ciphertext = crypt(integer, U)
decrypt = i2s(crypt(ciphertext, R))
print "Decrypted this message:", decrypt
assert hello == decrypt

#### tests ####
h = 'Hiya'
assert i2s(s2i(h)) == h

for i in range(10):
    U, R = keypair(64)
    msg = random.randint(1,10000)
    ciphertext = crypt(msg, U)
    decrypt = crypt(ciphertext, R)
    assert msg == decrypt

for i in range(10):
    a = gensafeprime.generate(64)
    m = gensafeprime.generate(64)
    x = invmod(a, m)
    assert (a*x) % m == 1

assert invmod(17, 3120) == 2753
warn("Passed assertions:", __file__)
