#!/usr/bin/env python

#     chal17.py - CBC padding oracle.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

import fakeserver
import cryptopals

print fakeserver.random_ciphertext_iv()

## tests ##
assert(cryptopals.pad_multiple("YELLOW SUBMARIN",8) == "YELLOW SUBMARIN\x04")
#cryptopals.warn("Passed assertions (" + __file__ + ")")
