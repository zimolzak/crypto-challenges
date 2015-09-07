#!/usr/bin/env python

#     chal28.py - Implement SHA-1 keyed MAC
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn, sha1, leftrotate, str2int
from Crypto.Hash import SHA

h = SHA.new()
h.update('Vanilla')
print "builtin says    ", h.hexdigest()
print "mine says     ", hex(sha1('Vanilla'))
print "builtin says    ", SHA.new("").hexdigest()
print "mine says     ", hex(sha1(""))

print "tqbf", hex(sha1("The quick brown fox jumps over the lazy dog"))
print "       2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"

#### tests, if any ####
warn("Passed assertions:", __file__)
