#!/usr/bin/env python

#     chal25.py - Break random access read/write CTR
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

import base64
from cryptopals import warn, ctr
from Crypto.Cipher import AES
import random

ecb_encrypted = base64.b64decode(''.join(open('25.txt', 'r').
                                         read().splitlines()))
plain = AES.new("YELLOW SUBMARINE", AES.MODE_ECB).decrypt(ecb_encrypted)
key = open('unknown_key.txt', 'r').read().splitlines()[0]
nonce = ""
for i in range(8):
    nonce += chr(random.randint(0,255))
ciphertext = ctr(plain, key, nonce, "little")

def edit(ciphertext, key, nonce, offset, newtext):
    plaintext = ctr(ciphertext, key, nonce, "little")
    nchars = len(newtext)
    plaintext = plaintext[0:offset] + newtext + plaintext[offset+nchars:]
    return ctr(plaintext, key, nonce, "little")

edited = edit(ciphertext, key, nonce, 4, 'COOL')

print '\n'.join(ctr(edited, key, nonce, "little").splitlines()[0:4])

#### tests, if any ####
assert len(nonce)==8
assert len(ciphertext) == len(plain)
assert plain.splitlines()[9] == "To just let it flow, let my concepts go "
warn("Passed assertions:", __file__)
