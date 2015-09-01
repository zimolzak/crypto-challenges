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
nonce = "\x00\x00\x00\x00\x00\x00\x00\x00" # 8 byte nonce

# print [ciphertext]

cipher = AES.new(key, AES.MODE_ECB)
plaintext = ""

# make keystream

keystream = ""
bs = len(key)
n_blocks = int(ceil(float(len(ciphertext)) / bs))

#generate whole keystream
for i in range(n_blocks):
    counter = int2str(i, bs - len(nonce), "little") # 8 byte counter
    # print([add_str(nonce,counter)]) # deleteme
    # print ([nonce+counter])
    keystream = keystream + cipher.encrypt(nonce + counter)

for i in range(len(ciphertext)):
    # need this loop otherwise maybe differing lengths
    plaintext = plaintext + xor_str(keystream[i], ciphertext[i])

#x = int2str(65534 * 256 + 1,8,"big")
#print "i2s"
#print [x]

#print [keystream]
print plaintext

#### tests ####
assert plaintext[-5:] == "baby "
warn("Passed assertions (" + __file__ + ")")
