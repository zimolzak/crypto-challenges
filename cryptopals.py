#     cryptopals.py - Assorted coversion and calculation functions for
#     Matasano crypto challenges (cryptopals.com).
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from __future__ import print_function
import math
import sys

def warn(*objs):
    """Easy and print-as-function way to output to STDERR."""
    print(*objs, file=sys.stderr)

def pad_multiple(text,k):
    """Return a text, padded out to a multiple of blocksize. Now uses
    actual PKCS #7 padding (see RFC 2315 section 10.3, note 2). k is
    the block size.
    """
    l = len(text)
    n_chars = k - (l % k) # Will always add >= 1 char, which is what we want.
    which_char = ["\x00"]
    for charnum in (range(1,k+1)):
        which_char.append(chr(charnum))
    return text + (which_char[n_chars] * n_chars)

class BadPaddingChar(Exception):
    def __init__(self, badchar, instr):
        self.badchar = badchar
        self.instr = instr
    def __str__(self):
        return "Bad " + repr(self.badchar) + repr(self.instr)
    
class MisplacedPaddingChar(Exception):
    def __init__(self, badchar, instr):
        self.badchar = badchar
        self.instr = instr
    def __str__(self):
        return "Misplaced " + repr(self.badchar) + repr(self.instr)
    
class BadPadding(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return "Bad padding: " + repr(self.value)

def strip_padding(string):
    n_chars = ord(string[-1])
    supposed_padding = string[-n_chars:]
    for char in supposed_padding:
        if char != string[-1]:
            raise BadPadding(string)
    return string[:-n_chars]
    
#### tests ####

for test_str in ["hello\x04", "hello\x02\x02"]:
    try:
        x = (strip_padding(test_str))
        assert test_str == "hello\x02\x02"
        assert x == "hello"
    except BadPadding as err:
        assert test_str == "hello\x04"

assert(pad_multiple("YELLOW SUBMARIN",8) == "YELLOW SUBMARIN\x01")
assert(pad_multiple("YELLOW SUBMARINE",8) == "YELLOW SUBMARINE" + "\x08" * 8)

warn("Passed assertions (" + __file__ + ")")
