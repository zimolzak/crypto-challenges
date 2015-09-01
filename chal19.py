#!/usr/bin/env python

#     chal19.py - Fixed-nonce CTR via substitutions
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

import base64
from cryptopals import warn, ctr, xor_str

key = open('unknown_key.txt', 'r').read().splitlines()[0]
nonce = "\x00\x00\x00\x00\x00\x00\x00\x00"
ciphertexts = []
for b64 in open('19.txt', 'r').read().splitlines():
    ciphertexts = ciphertexts + [ctr(base64.b64decode(b64),
                                    key, nonce, "little")]

#print len(ciphertexts)

# print transpose(ciphertexts[1], 16)

guesses = [''] * 256
for i in range(len(ciphertexts)):
    for c in range(256):
        if i == 0:
            guesses[c] = guesses[c] + chr(c)
        guesses[c] = guesses[c] + chr(ord(ciphertexts[i][15]) ^ c) # 0..end

for j in range(len(guesses)):
    print [guesses[j]]

# type in found keystream here
keystream = "\xcf\x8b\x10,zc\x91J\xd1\xbc\xa96t\xcf\xb2\x87\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
for i in range(len(ciphertexts)):
    line = ""
    for j in range(len(ciphertexts[i])):
        line = line + xor_str(ciphertexts[i][j], keystream[j])
    print line

#### tests ####

assert len(ciphertexts) == 40

warn("Passed assertions (" + __file__ + ")")
