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
hash = sha1(message).digest()

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

def verify(sig, message, pubkey):
    block = rsa.decrypt_string(signature, pubkey)
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
             chr(len(msg_to_forge)) +
             hash_mom)
bytes_to_add = (bits / 8) - len(block_mom)
block_mom += "\x00" * bytes_to_add
print [block_mom]

while (find_cube_root(rsa.s2i(block_mom)) ** 3) != rsa.s2i(block_mom):
    x = random.randint(1, 20)
    if x > 1:
        block_mom = (block_mom[:-x] +
                     chr(ord(block_mom[-x]) + 1) +
                     block_mom[-(x-1):])
    else:
        block_mom = (block_mom[:-x] +
                     chr(ord(block_mom[-x]) + 1))        
    if ord(block_mom[-3]) % 8 == 0:
        print [block_mom[-20:]]
        print len(block_mom)
print block_mom

#### tests ####
#assert verified == block
assert unpad(pkcs_1_5("Hello", 1024)) == "Hello"
assert len(block) == bits / 8
assert len(pkcs_1_5("HELLO", 1024)) == 1024 / 8
warn("Passed assertions:", __file__)
