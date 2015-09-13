#!/usr/bin/env python

#     chal34.py - Man in the middle vs. Diffie-Hellman
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
from diffie_hellman import Persona

alice = Persona()
bob = Persona()
mallory = Persona(evil=True, sucker=bob)

print "Innocent conversation:"
alice.handshake_with(bob)
alice.talk_to(bob)
print

print "Overheard conversation:"
alice.handshake_with(mallory)
alice.talk_to(mallory)

#### tests
warn("Passed assertions:", __file__)
