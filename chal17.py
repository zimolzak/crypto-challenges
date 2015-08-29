#!/usr/bin/env python

#     chal17.py - CBC padding oracle.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

import fakeserver
import cryptopals

print fakeserver.random_ciphertext_iv()

try:
    print cryptopals.strip_padding("hello\x04")
except cryptopals.BadPaddingChar:
    print "doh"

try:
    print cryptopals.strip_padding("hello\x03")
except cryptopals.BadPaddingChar as err:
    print "doh2: " + err.value

try:
    print cryptopals.strip_padding("hello\x04world")
except cryptopals.BadPaddingChar as err:
    print "doh2: " + err.value
except cryptopals.MisplacedPaddingChar as err:
    print "misplaced in: " + err.value

## tests ##
assert(cryptopals.pad_multiple("YELLOW SUBMARIN",8) == "YELLOW SUBMARIN\x04")
cryptopals.warn("Passed assertions (" + __file__ + ")")
