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
    
def strip_padding(string):
    for charnum in (range(0,32) + [127] ):
        # check for BAD padding chars in WHOLE string
        if chr(charnum) in ["\x04", "\t", "\n", "\r"]:
            continue
        elif chr(charnum) in string:
            raise BadPaddingChar(chr(charnum), string)
    if "\x04" in string:
        # check for MISPLACED non-\x04 in END of string
        for charnum in (range(128)):
            if chr(charnum) in ["\x04"]:
                continue
            elif chr(charnum) in string[string.find("\x04"):]:
                raise MisplacedPaddingChar(chr(charnum), string)
    return string.replace("\x04", "")

#### tests ####

for test_str in ["hello\x04", "hello\x03", "hello\x04world"]:
    try:
        x = (strip_padding(test_str))
        assert test_str == "hello\x04"
        assert x == "hello"
    except BadPaddingChar as err:
        assert test_str == "hello\x03"
    except MisplacedPaddingChar as err:
        assert test_str == "hello\x04world"

assert(pad_multiple("YELLOW SUBMARIN",8) == "YELLOW SUBMARIN\x04")

warn("Passed assertions (" + __file__ + ")")
