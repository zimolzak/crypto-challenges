#!/usr/bin/env python

#     chal47.py - RSA padding oracle, simple.
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
import rsa

def pkcs_1(string, bits):
    """Pad a string to specified number of bits.

    Start with 0x0001, then a bunch of 0xFF, then 0x00, then the
    string. Not to be confused with a slightly different function I
    wrote called pkcs_1_5().
    """
    assert len(string) < 256
    assert bits % 8 == 0
    byte_goal = bits / 8
    prepend = "\x00\x02"
    append = "\x00"
    bytes_to_add = (byte_goal -
                    (len(string) % byte_goal) -
                    len(prepend) -
                    len(append))
    return prepend + ("\xff" * bytes_to_add) + append + string

def oracle(ciphertext, privkey, bits):
    plaintext = rsa.decrypt_string(ciphertext, privkey)
    assert bits % 8 == 0
    bytes = bits / 8
    diff = bytes - len(plaintext)
    plaintext = "\x00" * diff + plaintext
    return plaintext[0] == "\x00" and plaintext[1] == "\x02"

Bits = 256
pubkey, privkey = rsa.keypair(Bits)
short_message = "kick it, CC"
m = pkcs_1(short_message, Bits)
c = rsa.encrypt_string(m, pubkey)

print "Oracle says that ciphertext conforms?", oracle(c, privkey, Bits)

#### tests ####
short_message2 = "testing"
m2 = pkcs_1(short_message2, Bits)
c2 = rsa.encrypt_string(m2, pubkey)
assert oracle(c2, privkey, Bits)
warn("Passed assertions:", __file__)
