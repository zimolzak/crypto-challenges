#!/usr/bin/env python

#     chal36.py - Implement secure remote password
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
from diffie_hellman import Persona, p as nist_prime, modexp
import random
from hashlib import sha256

class SRPEntity:
    def __init__(self, N, g, k, I, P):
        self.N = N
        self.g = g
        self.k = k
        self.email = I
        self.password = P

class Server(SRPEntity):
    def __init__(self, N, g, k, I, P):
        SRPEntity.__init__(self, N, g, k, I, P)
        self.salt = random.randint(0, 2 ** 32)
        xH = sha256(str(self.salt) + P).hexdigest()
        x = int('0x' + xH, 16)
        self.v = modexp(g, x, N)
    def take_logon(self, email, A):
        self.I = email # not really used. Would be a lookup.
        self.A = A
        self.b = random.randint(0, self.N - 1)                    # private
        self.B = self.k * self.v + modexp(self.g, self.b, self.N) # public
        return self.salt, self.B

class Client(SRPEntity):
    def __init__(self, N, g, k, I, P):
        SRPEntity.__init__(self, N, g, k, I, P)
        self.a = random.randint(0, self.N - 1) # private
        self.A = modexp(g, self.a, self.N)     # public
    def logon_to(self, robot):
        [self.salt, self.B] = robot.take_logon(self.email, self.A)
        

me = Client(nist_prime, 2, 3, 'billg@ms.com', 'PASSW0RD1')
you = Server(nist_prime, 2, 3, 'billg@ms.com', 'PASSW0RD1')

me.logon_to(you)


        
        


#### tests
warn("Passed assertions:", __file__)
