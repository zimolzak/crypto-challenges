#!/usr/bin/env python

#     chal38.py - Offline dictionary attack on simplified SRP
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
from srp import Client, Server
from diffie_hellman import p as nist_prime
import random

me = Client(nist_prime, 2, 3, 'billg@ms.com', 'PASSW0RD1', simple=True)
you = Server(nist_prime, 2, 3, 'billg@ms.com', 'PASSW0RD1', simple=True)
print "For benign,",
me.logon_to(you)
assert me.K == you.K
assert me.salt == you.salt

failure = Client(nist_prime, 2, 3, 'billg@ms.com', 'haha', simple=True)
print "For built to fail,",
failure.logon_to(you)
assert failure.K != you.K

mallory = Server(nist_prime, 2, 3, 'billg@ms.com', 'nopasswd', mitm=you)
print "\nFor MITM:"
me.logon_to(mallory)

warn("Passed assertions:", __file__)
