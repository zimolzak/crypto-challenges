#!/usr/bin/env python

#     chal24.py - Make a MT13397 stream cipher and analyze.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn, xor_str
from myrand import MTRNG
import random

letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
plaintext = ''
for i in range(random.randint(1,20)):
    plaintext += random.choice(letters)
plaintext += 'A' * 14

print plaintext

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

key = random.randint(0,255)
    
ciphertext = msc(plaintext, key)

decipher = msc(ciphertext, key)
print decipher

#### tests, if any ####
assert decipher == plaintext
warn("Passed assertions:", __file__)
