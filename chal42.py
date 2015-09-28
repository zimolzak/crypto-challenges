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
from chal40 import find_cube_root

message = 'Blah blah'

bits = 1024
U, R = rsa.keypair(bits)

hash = sha1("hi mom").digest()

def pkcs_1_5(string, bits):
    assert len(string) < 256
    assert bits % 8 == 0
    byte_goal = bits / 8
    prepend = "\x00\x01"
    append = "\x00ASN.1" + chr(len(string)) # not in real life
    bytes_to_add = (byte_goal -
                    (len(string) % byte_goal) -
                    len(prepend) -
                    len(append))
    return prepend + ("\xff" * bytes_to_add) + append + string

block = pkcs_1_5(hash, bits)
signature = rsa.encrypt_string(block, R) # Note: signing is w/ priv key.

def verify(sig, expected):
    block = rsa.decrypt_string(signature, U) # Verifying is w/ pub key.
    for i in range((bits/8) - len(block)):
        block = "\x00" + block
    return sha1(expected).digest() == unpad(block)

def unpad(string):
    state = "start"
    result = ""
    for i, c in enumerate(string):
        if i == 0 and c != "\x00":
            return "FAIL " + str(i) + str([c]) + "_"
        elif i == 0:
            continue
        if i == 1 and c != "\x01":
            return "FAIL " + str(i)
        elif i == 1:
            continue
        if i == 2 and c != "\xff":
            return "FAIL " + str(i)
        elif i == 2:
            state = "ff bytes"
        if state == "ff bytes" and c == "\xff":
            continue
        if state == "ff bytes" and c == "\x00":
            # 0ASN.1l____
            # i1234567
            len_hash = ord(string[i+6])
            loc_hash = i+7
            # Error coming up! Does not check for garbage after hash!
            return string[loc_hash : loc_hash + len_hash]
        else:
            return "FAIL " + str(i)

print verify(signature, "hi mom")

#### tests ####
#assert verified == block
assert unpad(pkcs_1_5("Hello", 1024)) == "Hello"
assert len(block) == bits / 8
assert len(pkcs_1_5("HELLO", 1024)) == 1024 / 8
warn("Passed assertions:", __file__)
