#!/usr/bin/env python

#     chal41.py - Recover unpadded RSA message
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
import rsa
from hashlib import sha1
import random

class RSAServer:
    def __init__(self, bits):
        self.log = []
        self.pub, self.priv = rsa.keypair(bits)
    def encrypt(self, message):
        result = {}
        result['ciphertext'] = rsa.encrypt_string(message, self.pub)
        result['pubkey'] = self.pub
        return result
    def decrypt(self, rsa_blob):
        """Expects numeric argument, not string."""
        this_hash = sha1(str(rsa_blob)).digest()
        for logged_hash in self.log:
            if this_hash == logged_hash:
                return "GO AWAY."
        self.log.append(this_hash)
        return rsa.decrypt_string(rsa_blob, self.priv)

message = 'This is just some dummy text to get us to about column 72....'
global_bits = len(message) * 8 / 2
alice = RSAServer(global_bits)

secret_for_bob = 'Only Bob is supposed to read this.'
breakme = alice.encrypt(secret_for_bob)
E = breakme['pubkey'][0] # pub key exponent
N = breakme['pubkey'][1] # public key modulus
C = breakme['ciphertext'] # long integer, not string

print "Bob calls Alice and receives..."
print alice.decrypt(C)
print

#### Mallory

print "Mallory calls Alice the 1st time and receives..."
print alice.decrypt(C)

print "Mallory calls w/ seemingly different string & receives..."
S = random.randint(2, 100000)
assert S % N > 1
Cp = (pow(S, E, N) * C) % N
Pp_string = alice.decrypt(Cp)
print Pp_string
Pp = rsa.s2i(Pp_string)
print "Alice's hash table suspects nothing..."
print alice.log
P = (Pp * rsa.invmod(S, N) ) % N
print "But Mallory now knows..."
print rsa.i2s(P)

#### tests ####
assert rsa.i2s(P) == secret_for_bob
warn("Passed assertions:", __file__)
