#!/usr/bin/env python

#     chal18.py - Implement CTR
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

import base64
from cryptopals import warn, ctr

ciphertext = base64.b64decode(
    "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
key = "YELLOW SUBMARINE"
nonce = "\x00\x00\x00\x00\x00\x00\x00\x00" # 8 byte nonce

plaintext = ctr(ciphertext, key, nonce, "little")
print plaintext

#### tests ####
assert plaintext[-5:] == "baby "
warn("Passed assertions (" + __file__ + ")")
