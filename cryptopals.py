#     cryptopals.py - Assorted coversion and calculation functions for
#     Matasano crypto challenges (cryptopals.com).
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

from __future__ import print_function
import math
import sys

def warn(*objs):
    """Easy and print-as-function way to output to STDERR."""
    print(*objs, file=sys.stderr)

def pad_multiple(text,blocksize):
    """Return a text, padded out to a multiple of blocksize."""
    n_chars = int(math.ceil(float(len(text)) / blocksize) * blocksize
                  - len(text))
    return text + "\x04" * n_chars

class BadPaddingChar(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)
    
def strip_valid_padding(string):
    for charnum in (range(0,32) + [127] ):
        if chr(charnum) in ["\x04", "\t", "\n", "\r"]:
            continue
        elif chr(charnum) in string:
            raise BadPaddingChar(string)
    # fixme - check for bad \x04 padding and strip
    return string
