#!/usr/bin/env python

#     chal25.py - Break random access read/write CTR
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
from fakeserver import ctr_ciphertext, edit_public, ctr_cheat

edited = edit_public(ctr_ciphertext, 4, 'COOL')
lines = ctr_cheat(edited).splitlines()[0:4]
print '\n'.join(lines)

#### tests, if any ####
assert lines[0] == "I'm COOL and I'm ringin' the bell "
warn("Passed assertions:", __file__)
