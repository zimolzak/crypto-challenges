#!/usr/bin/env python

#     chal46.py - RSA parity oracle
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
import rsa
import random

print "Generating keypair..."
U, R = rsa.keypair(1024)

def parity(ciphertext, priv_key):
    """Ciphertext is an integer."""
    decrypt_int = rsa.crypt(ciphertext, R)
    return int(decrypt_int % 2) # int, not a long.

print "Checking bunch of parities..."
P = []
for i in range(100):
    rand_chars = ''
    for j in range(32):
        if j % 8 == 7 and j < 31:
            rand_chars += " "
        else:
            rand_chars += chr(random.randint(97,122))
    ciphertext = rsa.encrypt_string(rand_chars, U)
    P.append(parity(ciphertext, R))

print P
print "Proportion odd:", reduce(lambda x, y: x+y, P) / float(len(P))

#### tests ####

warn("Passed assertions:", __file__)
