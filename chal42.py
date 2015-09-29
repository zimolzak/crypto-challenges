#!/usr/bin/env python

#     chal42.py - e=3 RSA
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn, cuberoot
import rsa
import random
import cryptopals
from hashlib import sha1

message = 'Blah blah'
bits = 1024
U, R = rsa.keypair(bits)
hash = sha1(message).digest()

def pkcs_1_5(string, bits):
    """Pad a string to specified number of bits. Specifically, start with
    0x0001, then a bunch of 0xFF, then 0x00, then some imitation ASN.1
    data, then the string. In real life, ASN.1 data encodes the length
    of the string, which I do too, to a point. There's also some other
    data in there, and I completely ignore the implementation of
    'other ASN.1 data'.
    """
    assert len(string) < 256
    assert bits % 8 == 0
    byte_goal = bits / 8
    prepend = "\x00\x01"
    append = "\x00ASN.1" + chr(len(string)) 
    bytes_to_add = (byte_goal -
                    (len(string) % byte_goal) -
                    len(prepend) -
                    len(append))
    return prepend + ("\xff" * bytes_to_add) + append + string

block = pkcs_1_5(hash, bits)
signature = rsa.encrypt_string(block, R) # Note: signing is w/ priv key.

def verify(sig, message, pubkey):
    block = rsa.decrypt_string(sig, pubkey)
    for i in range((bits/8) - len(block)):
        block = "\x00" + block
    return sha1(message).digest() == unpad(block)

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

print "A user received message:", message
print "Along with signature..."
print signature
print "Does it verify?"
print verify(signature, message, U)
print

#### Forging

msg_to_forge = "hi mom"
hash_mom = sha1(msg_to_forge).digest()
block_mom = ("\x00\x01\xff\xff\x00ASN.1" +
             chr(len(hash_mom)) +
             hash_mom)
bytes_to_add = (bits / 8) - len(block_mom)
block_mom += "\x00" * bytes_to_add
block_mom_cube = "\x00" + rsa.i2s(cuberoot(rsa.s2i(block_mom)) ** 3)
forged_sig = cuberoot(rsa.s2i(block_mom_cube))

#### Check the sig

print "A poor fool received message:", msg_to_forge
print "Along with signature..."
print forged_sig
print "Does it verify?"
result = verify(forged_sig, msg_to_forge, U)
print result
print

#### tests ####
assert result
assert unpad(pkcs_1_5("Hello", 1024)) == "Hello"
assert len(block) == bits / 8
assert len(pkcs_1_5("HELLO", 1024)) == 1024 / 8
warn("Passed assertions:", __file__)
