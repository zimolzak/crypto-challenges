#!/usr/bin/env python

#     chal40.py - RSA broadcast
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn, cuberoot
import rsa
import copy

k = 3 # How many times to encrypt the same plaintext, under different
      # public keys.

message = 'Hello, world! I am gonna encrypt this thrice; uh oh.'
bits = len(message) * 8 / 2
c = [None]*k
n = [None]*k
for i in range(k):
    U, R = rsa.keypair(bits)
    ciphertext = rsa.encrypt_string(message, U)
    c[i] = ciphertext
    n[i] = U[1] # the second part of the pubkey
    print "public     " + str(U[1])[:60] + "...."
    print "ciphertext " + str(ciphertext)[:60] + "...."

decrypt = rsa.decrypt_string(ciphertext, R)
print
print "Bob gets this message:", decrypt

#### Eve

# Calculate products of the moduli (pubkeys) EXCEPT pubkey number i.
ms = [None]*k
for i in range(k):
    x = copy.copy(n)
    del x[i]
    ms[i] = reduce(lambda a, b: a*b, x)

# Work thru Chinese Remainder Theorem
result = 0
for i in range(k):
    result += c[i] * ms[i] * rsa.invmod(ms[i], n[i])
result = result % reduce(lambda a, b: a*b, n)

# Get final text

overheard = rsa.i2s(cuberoot(result))

print "Eve hears this message:", overheard

#### tests ####
assert message == decrypt
assert message == overheard
assert decrypt == overheard
warn("Passed assertions:", __file__)
