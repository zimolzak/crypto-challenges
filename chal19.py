#!/usr/bin/env python

#     chal19.py - Fixed-nonce CTR via substitutions
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

import base64
from cryptopals import warn, ctr
from rkxor import find_keysize

key = open('unknown_key.txt', 'r').read().splitlines()[0]
nonce = "\x00\x00\x00\x00\x00\x00\x00\x00"
ciphertexts = []
for b64 in open('19.txt', 'r').read().splitlines():
    ciphertexts = ciphertexts + [ctr(base64.b64decode(b64),
                                    key, nonce, "little")]

print len(ciphertexts)

print find_keysize(ciphertexts[1], 7)



#### tests ####

assert len(ciphertexts) == 40

warn("Passed assertions (" + __file__ + ")")
