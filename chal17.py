#!/usr/bin/env python

#     chal17.py - CBC padding oracle.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

import fakeserver
import cryptopals

#from Crypto.Cipher import AES #deleteme





## tests ##
for i in range(100):
    [ciph, iv] = fakeserver.random_ciphertext_iv()
    assert(fakeserver.padding_is_valid(ciph, iv))
    #    key = open('unknown_key.txt', 'r').read().splitlines()[0]
    #    cipher = AES.new(key, AES.MODE_CBC, iv)
    #    print cipher.decrypt(ciph)


cryptopals.warn("Passed assertions (" + __file__ + ")")
