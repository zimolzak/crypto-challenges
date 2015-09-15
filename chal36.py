#!/usr/bin/env python

#     chal36.py - Implement secure remote password
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
from srp import Client, Server
from diffie_hellman import p as nist_prime

me = Client(nist_prime, 2, 3, 'billg@ms.com', 'PASSW0RD1')
you = Server(nist_prime, 2, 3, 'billg@ms.com', 'PASSW0RD1')

me.logon_to(you)

#### tests
assert me.K == you.K
assert me.salt == you.salt
warn("Passed assertions:", __file__)
