#     sha_analysis.py - Functions for analysis of SHA-1 Message
#     Authentication
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import str2int, leftrotate, warn
import math

def sha_padding(message):
    assert type(message) == type(str())
    ml = 8 * len(message) # ML is in bits
    n_bytes_to_add = (448 - (ml % 512)) / 8
    padding_string = ""
    for i in range(n_bytes_to_add):
        if i > 0:
            padding_string += '\x00'
        else:
            padding_string += '\x80'
    for i in range(8):
        byte_val = ml >> (64 - 8 * (i + 1)) & 0xff
        # Big endian means R shift by 56, 48, ... , 8, 0.
        padding_string += chr(byte_val)
    message += padding_string
    assert len(message) % (512/8) == 0
    return padding_string

#### tests ####
warn("Passed assertions (" + __file__ + ")")
