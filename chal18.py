#!/usr/bin/env python

#     chal18.py - Implement CTR
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

import base64
from cryptopals import xor_str, warn
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
for i in range(int(ceil(float(len(ciphertext)) / bs))):
    # i is which block of keystream to gen
    for j in range(bs):
        # j is which byte to gen
        print i >> j
        keystream = keystream + chr(ord(nonce[j]) + (i >> (j * 8)))

for i in range(len(ciphertext)):
#    print ' '.join([str(i), keystream[i], ciphertext[i]])
    plaintext = plaintext + xor_str(keystream[i], ciphertext[i])

#print [keystream]
print plaintext

#### tests ####
warn("Passed assertions (" + __file__ + ")")
