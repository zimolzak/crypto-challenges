#!/usr/bin/env python

#     chal34.py - Man in the middle vs. Diffie-Hellman
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
from diffie_hellman import get_pubkey_exp, p as p0, g as g0, modexp
from hashlib import sha1
from Crypto import Random
from Crypto.Cipher import AES

allbytes = [chr(i) for i in range(256)]

def int2str(x):
    # Little endian, but who cares? Grab all of it unlike my previous
    # function.
    output = ""
    while(x):
        n = x & 0xff
        output += chr(n)
        x = x >> 8
    return output

class Persona:
    def __init__(self, sucker=None, modulus=p0, base=g0, evil=False):
        self.p = modulus
        self.g = base
        self.new_keypair()
        self.sucker = sucker # only relevant for evil MITM
        self.evil = evil
    def new_keypair(self):
        keypair = get_pubkey_exp(self.p, self.g)
        self.public = keypair[0]
        self.private = keypair[1]
    def calc_session_key(self):
        self.s = int2str(modexp(self.foreign_public, self.private, self.p))
    #### methods for setup
    def handshake_with(self, robot):
        robot.take_my_key(self.p, self.g, self.public)
        self.foreign_public = robot.send_your_key()
        self.calc_session_key()
    def take_my_key(self, p, g, A):
        self.p = p # should overwrite the init.
        self.g = g
        self.foreign_public = A
        self.new_keypair()
        self.calc_session_key()
        if self.evil:
            self.sucker.take_my_key(p, g, p)
    def send_your_key(self):
        if not self.evil:
            return self.public
        else:
            self.sucker_public = self.sucker.send_your_key()
            return self.p
    #### methods for messaging
    def talk_to(self, robot):
        message = "Only you can make all this world seem right.    "
        # len must be = 0 (mod 16)
        iv = Random.new().read(16)
        aeskey = sha1(self.s).digest()[0:16]
        encryptor = AES.new(aeskey, AES.MODE_CBC, iv)
        ciphertext = encryptor.encrypt(message)
        robot.take_message(ciphertext, iv)
        [received, iv2] = robot.send_your_message()
        decryptor = AES.new(aeskey, AES.MODE_CBC, iv2)
        decrypt = decryptor.decrypt(received)
        print "My friend says:", decrypt
        assert message == decrypt
    def take_message(self, ct, iv):
        if not self.evil:
            aeskey = sha1(self.s).digest()[0:16]
            decryptor = AES.new(aeskey, AES.MODE_CBC, iv)
            self.robo_decrypt = decryptor.decrypt(ct)
        else:
            aeskey = sha1('').digest()[0:16]
            decryptor = AES.new(aeskey, AES.MODE_CBC, iv)
            self.atob = decryptor.decrypt(ct)
            print "SNOOP A to B", self.atob
            self.sucker.take_message(ct, iv)
    def send_your_message(self):
        if not self.evil:
            aeskey = sha1(self.s).digest()[0:16]
            iv = Random.new().read(16)
            encryptor = AES.new(aeskey, AES.MODE_CBC, iv)
            return [encryptor.encrypt(self.robo_decrypt), iv]
        else:
            aeskey = sha1('').digest()[0:16]
            [ct, iv] = self.sucker.send_your_message()
            decryptor = AES.new(aeskey, AES.MODE_CBC, iv)
            btoa = decryptor.decrypt(ct)
            print "SNOOP B to A", btoa
            assert btoa == self.atob
            return [ct, iv]
        
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
