#!/usr/bin/env python

#     chal18.py - Implement CTR
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

import base64
from cryptopals import xor_str, warn, add_str, int2str
from math import ceil
from Crypto.Cipher import AES

ciphertext = base64.b64decode(
    "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
key = "YELLOW SUBMARINE"
nonce = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

# print [ciphertext]

cipher = AES.new(key, AES.MODE_ECB)
keystream = cipher.encrypt(nonce)
plaintext = ""

# make keystream

keystream = ""
assert len(key) == len(nonce)
bs = len(key)
n_blocks = int(ceil(float(len(ciphertext)) / bs))

for i in range(n_blocks):
    counter = int2str(i, bs)
    print([add_str(nonce,counter)]) # deleteme
    keystream = keystream + cipher.encrypt(add_str(nonce, counter))

for i in range(len(ciphertext)):
    # need this loop otherwise maybe differing lengths
    plaintext = plaintext + xor_str(keystream[i], ciphertext[i])

#x = int2str(65535 * 256,8)
#print "i2s"
#print [x]

#print [keystream]
print plaintext

#### tests ####
warn("Passed assertions (" + __file__ + ")")
