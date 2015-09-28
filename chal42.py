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

block = pkcs_1_5(hash, bits)
signature = rsa.encrypt_string(block, R) # note sign w/ priv key
verified = rsa.decrypt_string(signature, U) # verify w/ pub key
for i in range((bits/8) - len(verified)):
    verified = "\x00" + verified
print [verified]

def verify(sig, expected):
    return False

#### tests ####
assert verified == block
assert len(block) == bits / 8
assert len(pkcs_1_5("HELLO", 1024)) == 1024 / 8
warn("Passed assertions:", __file__)
