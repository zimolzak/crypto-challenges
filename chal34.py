#!/usr/bin/env python

#     chal34.py - Man in the middle vs. Diffie-Hellman
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
from diffie_hellman import get_pubkey_exp, p as p0, g as g0, modexp
from hashlib import sha1
#import random
from Crypto import Random
from Crypto.Cipher import AES

allbytes = [chr(i) for i in range(256)]

def int2str(x):
    # little endian, but who cares? Grab all of it unlike my previous
    # func.
    output = ""
    while(x):
        n = x & 0xff
        output += chr(n)
        x = x >> 8
    return output

class Persona:
    def __init__(self, modulus=p0, base=g0, evil=False):
        self.p = modulus
        self.g = base
        self.new_keypair()
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
        self.new_keypair()
        self.foreign_public = A
        self.calc_session_key()
    def send_your_key(self):
        return self.public
    #### methods for messaging
    def talk_to(self, robot):
        message = "Only you can make all this world seem right.    " #len48
        iv = Random.new().read(16) # maybe
        aeskey = sha1(self.s).digest()[0:16] # maybe
        encryptor = AES.new(aeskey, AES.MODE_CBC, iv)
        ciphertext = encryptor.encrypt(message) # maybe
        robot.take_message(ciphertext, iv)
        [received, iv2] = robot.send_your_message()
        decryptor = AES.new(aeskey, AES.MODE_CBC, iv2)
        decrypt = decryptor.decrypt(received) # maybe
        print decrypt
    def take_message(self, ct, iv):
        aeskey = sha1(self.s).digest()[0:16] # maybe
        decryptor = AES.new(aeskey, AES.MODE_CBC, iv)
        self.robo_decrypt = decryptor.decrypt(ct)
    def send_your_message(self):
        aeskey = sha1(self.s).digest()[0:16] # maybe
        iv = Random.new().read(16) # maybe
        encryptor = AES.new(aeskey, AES.MODE_CBC, iv)
        return [encryptor.encrypt(self.robo_decrypt), iv] # maybe
        
alice = Persona()
bob = Persona()

alice.handshake_with(bob)
alice.talk_to(bob)

#### tests
warn("Passed assertions:", __file__)
