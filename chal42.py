#!/usr/bin/env python

#     chal42.py - e=3 RSA
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
import rsa
import random
import cryptopals
from hashlib import sha1

message = 'Blah blah'

bits = 1024
U, R = rsa.keypair(bits)

m2 = 0x0002
c2 = rsa.crypt(m2, U)
print "The block", m2, "encrypts in e=3 RSA to", c2
d2 = rsa.crypt(c2, R)
print "Decrypted this:", d2

def sentence(bits):
    letters = []
    for i in range(ord('a'), ord('z')+1):
        letters.append(chr(i))
    s = ""
    while len(s) < (bits / 8):
        if len(s) % 8 == 7:
            s += " "
            continue
        else:
            s += random.choice(letters)
    return s

S = sentence(bits * 3)
print cryptopals.text2blocks(S, bits / 8)

hash = sha1("hi mom").digest()

def pkcs_1_5(string, bits):
    assert bits % 8 == 0
    byte_goal = bits / 8
    prepend = "\x00\x01"
    append = "\x00ASN.1"
    bytes_to_add = (byte_goal -
                    (len(string) % byte_goal) -
                    len(prepend) -
                    len(append))
    return prepend + ("\xff" * bytes_to_add) + append + string

print [pkcs_1_5(hash, bits)]

#### tests ####
assert d2 == m2
assert len(pkcs_1_5("HELLO", 1024)) == 1024 / 8
warn("Passed assertions:", __file__)
