#!/usr/bin/env python

#     chal24.py - Make a MT13397 stream cipher and analyze.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn, xor_str
from myrand import MTRNG
import random

#### Construct a plaintext

letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
plaintext = ''
for i in range(random.randint(1,20)):
    plaintext += random.choice(letters)
plaintext += 'A' * 14
print plaintext

#### Encrypt it and test decryption.

def msc(text, seed):
    """Mersenne stream cipher"""
    assert seed < 2**16
    rng = MTRNG(seed)
    output = ""
    num = 0
    for text_char in text:
        if num == 0:
            num = rng.extract_number() # get a new 4 bytes
        keystream_num = num & 0xff # one byte at a time
        num = num >> 8
        output += chr(keystream_num ^ ord(text_char))
    return output

key = random.randint(0,65535)
ciphertext = msc(plaintext, key)
decipher = msc(ciphertext, key)
print decipher

#### Brute-force the encryption 

winning_key = 0
for keytry in range(65536):
    # Seems to brute-force 1000 per 3 sec. Worst case 3.28 min.
    decipher_try = msc(ciphertext, keytry)
    if keytry % 1000 == 0:
        print keytry
    if decipher_try[-14:] == "A" * 14:
        print "Broken with key", keytry
        winning_key = keytry
        break

winning_decrypt = msc(ciphertext, winning_key)
print winning_decrypt

# Next step: generate a random "password reset token" using MT19937
# seeded from the current time. Write a function to check if any given
# password token is actually the product of an MT19937 PRNG seeded
# with the current time.

#### tests, if any ####
assert decipher == plaintext
assert winning_decrypt == plaintext
warn("Passed assertions:", __file__)
