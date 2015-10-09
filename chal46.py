#!/usr/bin/env python

#     chal46.py - RSA parity oracle
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
import rsa
import random
import base64
from math import log

print "Generating keypair..."
pubkey, privkey = rsa.keypair(1024)
print "Done!"

def parity(ciphertext):
    """Ciphertext is an integer."""
    decrypt_int = rsa.crypt(ciphertext, privkey)
    return int(decrypt_int % 2) # int, not a long.

b64s = 'VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=='

# um, if e=3, I don't think this string wraps the modulus. So in
# theory, I think we could just cube-root it, but oh well.

plaintext = base64.b64decode(b64s)
ciphertext = rsa.encrypt_string(plaintext, pubkey)

def double(ciphertext):
    return ciphertext * rsa.crypt(2, pubkey)

def cleanup(string):
    safe = ''
    for c in string:
        if 32 <= ord(c) <= 126:
            safe += c
    return safe

bounds = [0, pubkey[1]]
for i in range(1000):
    p = parity(double(ciphertext))
    half_the_dist = (bounds[1] - bounds[0]) / 2
    if p == 0:
        bounds = [bounds[0], bounds[1] -  half_the_dist]
    elif p == 1:
        bounds = [bounds[0] + half_the_dist, bounds[1]]
    ciphertext = ciphertext >> 1
    if i % 8 == 7:
        # print log(half_the_dist, 2)
        print cleanup(rsa.i2s(bounds[1]))

#### tests ####

warn("Passed assertions:", __file__)
