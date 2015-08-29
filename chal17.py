#!/usr/bin/env python

#     chal17.py - CBC padding oracle.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

import random
import base64
from cryptopals import pad_multiple

def random_ciphertext_iv():
    from Crypto import Random
    from Crypto.Cipher import AES
    blocksize = 16
    plaintext = base64.b64decode(random.choice(
        open('17.txt', 'r').read().splitlines()
    ))
    key = open('unknown_key.txt', 'r').read().splitlines()[0]
    print "len is --> " + str(len(key))
    plaintext = pad_multiple(plaintext, AES.block_size)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return [cipher.encrypt(plaintext), iv]

print random_ciphertext_iv()

assert(pad_multiple("YELLOW SUBMARIN",8) == "YELLOW SUBMARIN\x04")

print "Passed assertions (" + __file__ + ")"
