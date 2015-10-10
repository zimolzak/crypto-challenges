#!/usr/bin/env python

#     chal46.py - RSA parity oracle
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
import rsa
import base64
import time

print "Generating keypair..."
pubkey, privkey = rsa.keypair(1024)
print "Done!"
e = pubkey[0]
n = pubkey[1]

def parity(ciphertext):
    """Ciphertext is an integer. Depends on privkey."""
    decrypt_int = rsa.crypt(ciphertext, privkey)
    return int(decrypt_int % 2) # int, not a long.

def multiply(ciphertext, k, e, n):
    return (ciphertext * k ** e) % n

def cleanup(string, substitution=''):
    safe = ''
    for c in string:
        if 32 <= ord(c) <= 126:
            safe += c
        else:
            safe += substitution
    return safe

b64s = 'VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=='
plaintext = base64.b64decode(b64s)
ciphertext = rsa.encrypt_string(plaintext, pubkey)
# um, if e=3, I don't think this string wraps the modulus. So in
# theory, I think we could just cube-root it, but oh well.

bounds = [0, n]
start = time.time()
for i in range(2048):
    p = parity(multiply(ciphertext, 2**(i+1), e, n))
    half_the_dist = (bounds[1] - bounds[0]) / 2
    if p == 0:
        bounds = [bounds[0], bounds[1] -  half_the_dist]
    elif p == 1:
        bounds = [bounds[0] + half_the_dist, bounds[1]]
    if i % 16 == 0:
        print p, i, cleanup(rsa.i2s(bounds[1]), '_') # get 256 char wide screen

end = time.time()
dur = round(end - start, 1)
print "--------"
for b in bounds:
    print rsa.i2s(b)

print "2048 oracularities in", dur, "s =", round(2048 / dur, 1), "per s."

#### tests ####

hi = 'Hi'
c_hi = rsa.encrypt_string(hi, pubkey)
D = multiply(c_hi, 2, pubkey[0], pubkey[1])
assert rsa.s2i(hi) * 2 == rsa.crypt(D, privkey)

warn("Passed assertions:", __file__)
