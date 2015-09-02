#!/usr/bin/env python

#     chal20.py - Fixed-nonce CTR via statistics
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

import base64
from cryptopals import warn, ctr, xor_str, xor_uneq
from rkxor import break_cipher_given_keysize, xor_char_str

key = open('unknown_key.txt', 'r').read().splitlines()[0]
nonce = "\x00\x00\x00\x00\x00\x00\x00\x00"
ciphertexts = []
for b64 in open('20.txt', 'r').read().splitlines():
    ciphertexts = ciphertexts + [ctr(base64.b64decode(b64),
                                    key, nonce, "little")]

minimum = 9999
maximum = 0
for i in range(len(ciphertexts)):
    if len(ciphertexts[i]) < minimum:
        minimum = len(ciphertexts[i])
    if len(ciphertexts[i]) > maximum:
        maximum = len(ciphertexts[i])

#print "max", maximum

keystream = ""
for k in range(maximum):
    concat = ""
    for c in ciphertexts:
        try:
            concat += c[k]
        except IndexError:
            pass
    a = break_cipher_given_keysize([1], concat, xor_char_str)
    keystream += a[0][0]

#print
#print "Keystream:", a[0]
#print "First", minimum, "bytes of plaintext", a[1]
#keystream = a[0][0]

keystream = "\xcf" + keystream # somehow it misses the 1st byte

# first 95 bytes are ok

#print [keystream[96:]]
#keystream = keystream[0:95] + xor_str(xor_str(keystream[95],'j'), 'k') + keystream[96:]
#keystream = keystream[0:96] + xor_str(xor_str(keystream[96],'"'), 'n') + keystream[97:]

for c in ciphertexts:
    print xor_uneq(c, keystream)

longline46 = "I used to roll up, this is a hold up, ain't nuthin' funny / Stop smiling, be still, don't nuthin' move but the money"
keystream = xor_uneq(ciphertexts[46], longline46)

print
print "After Google:"
print

plaintexts = []
for c in ciphertexts:
    print xor_uneq(c, keystream)
    plaintexts += [xor_uneq(c, keystream)]

#### tests ####
assert len(ciphertexts) == 60
assert plaintexts[59] == "And we outta here / Yo, what happened to peace? / Peace"
warn("Passed assertions (" + __file__ + ")")
