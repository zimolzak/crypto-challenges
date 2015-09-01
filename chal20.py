#!/usr/bin/env python

#     chal20.py - Fixed-nonce CTR via statistics
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

import base64
from cryptopals import warn, ctr, xor_str
from rkxor import break_cipher_given_keysize, xor_char_str

key = open('unknown_key.txt', 'r').read().splitlines()[0]
nonce = "\x00\x00\x00\x00\x00\x00\x00\x00"
ciphertexts = []
for b64 in open('20.txt', 'r').read().splitlines():
    ciphertexts = ciphertexts + [ctr(base64.b64decode(b64),
                                    key, nonce, "little")]

min = 9999
for i in range(len(ciphertexts)):
    if len(ciphertexts[i]) < min:
        min = len(ciphertexts[i])

concat = ""
for i in range(len(ciphertexts)):
    concat += ciphertexts[i][0:min]

a = break_cipher_given_keysize([min], concat, xor_char_str)

print
print "Keystream:", a[0]
print "First bit of plaintext", a[1]

#### tests ####
assert len(ciphertexts) == 60
warn("Passed assertions (" + __file__ + ")")
