#!/usr/bin/env python

#     chal36.py - Implement secure remote password
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
from srp import Client, Server
from diffie_hellman import p as nist_prime
import random

me = Client(nist_prime, 2, 3, 'billg@ms.com', 'PASSW0RD1')
you = Server(nist_prime, 2, 3, 'billg@ms.com', 'PASSW0RD1')
print "For benign,",
me.logon_to(you)
assert me.K == you.K
assert me.salt == you.salt

failure = Client(nist_prime, 2, 3, 'billg@ms.com', 'haha')
print "For built to fail,",
failure.logon_to(you)
assert failure.K != you.K

for k in range(0,11):
    pw = ''
    for i in range(8):
        pw = pw + chr(random.randint(97,122))
    print "A%N=0 password", pw,
    sneak = Client(nist_prime, 2, 3, 'billg@ms.com', pw, ntimes=k)
    sneak.logon_to(you)
    assert sneak.K == you.K
    assert sneak.salt == you.salt

warn("Passed assertions:", __file__)
