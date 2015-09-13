#     diffie_hellman.py - Implement Diffie-Hellman
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
import random
from hashlib import sha1
from Crypto import Random
from Crypto.Cipher import AES

p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

g = 2

def modexp(b, e, m):
    c = 1
    b = b % m
    while e > 0:
        if e % 2 == 1:
            c = (c * b) % m
        e = e >> 1
        b = (b * b) % m
    return c

def get_pubkey_exp(p_mod, g_base):
    a_exp = random.randint(0, p_mod - 1)
    return [modexp(g_base, a_exp, p_mod), a_exp]

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
    def __init__(self, sucker=None, modulus=p, base=g, evil=False):
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
            print "SNOOP A to B:", self.atob
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
            print "SNOOP B to A:", btoa
            assert btoa == self.atob
            return [ct, iv]
        
#### tests
for i in range(1,38):
    for j in range(1,38):
        for k in range(1,38):
            assert (i ** j) % k == modexp(i, j, k)
warn("Passed assertions:", __file__)
