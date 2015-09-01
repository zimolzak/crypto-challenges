#!/usr/bin/env python

#     chal19.py - Fixed-nonce CTR via substitutions
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

import base64
from cryptopals import warn, ctr, xor_str

key = open('unknown_key.txt', 'r').read().splitlines()[0]
nonce = "\x00\x00\x00\x00\x00\x00\x00\x00"
ciphertexts = []
for b64 in open('19.txt', 'r').read().splitlines():
    ciphertexts = ciphertexts + [ctr(base64.b64decode(b64),
                                    key, nonce, "little")]

guesses = [''] * 256
for i in range(len(ciphertexts)):

    # This loop is for manual use only. Serves no purpose in the final
    # decryption step. Manually adjust the [i][15] number, and examine
    # the printout for strings that look like slices of English text
    # (mainly lowercase and spaces, few punctuation marks, no ASCII >
    # 127). First char of each string is the J'th byte in the
    # keystream.

    for c in range(256):
        if i == 0:
            guesses[c] = guesses[c] + chr(c)
        guesses[c] = guesses[c] + chr(ord(ciphertexts[i][15]) ^ c)

# for j in range(len(guesses)):
#    print [guesses[j]]

# After finding the first 16 bytes of keystream, I easily deduced the
# full text from Google. Now I can deduce the whole keystream from the
# longest line, and then decrypt as follows:

line00 = "I have met them at close of day"
line04 = "I have passed with a nod of the head"
line37 = "He, too, has been changed in his turn,"
print "guesses:"
print [xor_str(ciphertexts[0][0:len(line00)], line00)]
print [xor_str(ciphertexts[4][0:len(line04)], line04)]
print [xor_str(ciphertexts[37][0:len(line37)], line37)]

keystream = xor_str(ciphertexts[37][0:len(line37)], line37)
    
plaintexts = [""] * len(ciphertexts)
for i in range(len(ciphertexts)):
    for j in range(len(ciphertexts[i])):
        plaintexts[i] = plaintexts[i] + xor_str(ciphertexts[i][j],
                                                keystream[j])

print '\n'.join(plaintexts)

#### tests ####

assert plaintexts[1] == "Coming with vivid faces"

assert len(ciphertexts) == 40

warn("Passed assertions (" + __file__ + ")")
