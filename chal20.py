#!/usr/bin/env python

#     chal20.py - Fixed-nonce CTR via statistics
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

import base64
from cryptopals import warn, ctr, xor_str, xor_uneq
from rkxor import break_cipher_given_keysize, xor_char_str

key = open('unknown_key.txt', 'r').read().splitlines()[0]
nonce = "\x00\x00\x00\x00\x00\x00\x00\x00"
ciphertexts = []
for b64 in open('20.txt', 'r').read().splitlines():
    ciphertexts = ciphertexts + [ctr(base64.b64decode(b64),
                                    key, nonce, "little")]

minimum = 9999
maximum = 0
for i in range(len(ciphertexts)):
    if len(ciphertexts[i]) < minimum:
        minimum = len(ciphertexts[i])
    if len(ciphertexts[i]) > maximum:
        maximum = len(ciphertexts[i])

print "max", maximum

concat = ""
for i in range(len(ciphertexts)):
    concat += ciphertexts[i][0:minimum]

a = break_cipher_given_keysize([minimum], concat, xor_char_str)

print
print "Keystream:", a[0]
print "First", minimum, "bytes of plaintext", a[1]

keystream = a[0][0]

keystream = "\xcf" + keystream # somehow it misses the 1st byte

for c in ciphertexts:
    print xor_uneq(c, keystream)

#### tests ####
assert len(ciphertexts) == 60
warn("Passed assertions (" + __file__ + ")")
