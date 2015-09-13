#!/usr/bin/env python

#     chal35.py - Man in the middle, changing "g" param this time.
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
from diffie_hellman import Persona

alice = Persona()
bob = Persona()

M = [Persona(evil=True, sucker=bob, mode=x) for x in range(1,4)]

print "Innocent conversation:"
alice.handshake_with(bob)
alice.talk_to(bob)

for i in range(len(M)):
    print
    print "Overheard", i, ":"
    alice.handshake_with(M[i])
    alice.talk_to(M[i])

#### tests
warn("Passed assertions:", __file__)
