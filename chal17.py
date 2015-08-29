#!/usr/bin/env python

#     chal17.py - CBC padding oracle.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

import fakeserver
import cryptopals

[ciph, iv] = fakeserver.random_ciphertext_iv()

# my Plaintext 
# decrypt block C2 of ciphertext (up to N blocks):
#     my GG
#     increase bytes guessed (up to blocksize)
#         come up with guess g until server says valid
#             change bytes bbb at end of C1 to bbb ^ gGG ^ \x03\x03\x03
#             (valid is defined as: send [C1C2, iv])
#         prepend valid guess g onto the former GG to make GGG
#     append GGGGGGGGGGGGGGGG onto Plaintext


#### tests ####

for i in range(100):
    [ciph, iv] = fakeserver.random_ciphertext_iv()
    assert(fakeserver.padding_is_valid(ciph, iv))

cryptopals.warn("Passed assertions (" + __file__ + ")")
