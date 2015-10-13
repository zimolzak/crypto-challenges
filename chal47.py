#!/usr/bin/env python

#     chal47.py - RSA padding oracle, simple.
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
import rsa
from random import randint

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
    """bits should equal the max bits of a message, not bit length of
    key.
    """
    plaintext = rsa.decrypt_string(ciphertext, privkey)
    #pt_n = pow(ciphertext, privkey[0], privkey[1])
    #print pt_n
    #assert pt_n < privkey[1]
    #print [plaintext]
    assert bits % 8 == 0
    bytes = bits / 8
    diff = bytes - len(plaintext)
    plaintext = "\x00" * diff + plaintext
    assert len(plaintext) == bytes, len(plaintext)
    if plaintext[0] == "\x00":
        print [plaintext[0:2]]
    return plaintext[0] == "\x00" and plaintext[1] == "\x02"

Bits = 256
pubkey, privkey = rsa.keypair(Bits)
short_message = "kick it, CC"
m = pkcs_1(short_message, Bits * 2) # Bits*2 = length of n
c = rsa.encrypt_string(m, pubkey)

print "Oracle says that raw ciphertext conforms?", oracle(c, privkey, Bits * 2)

#### Step 1.

e = pubkey[0]
n = pubkey[1]
k = Bits * 2 / 8 # Length of n in bytes
B = 2 ** (8 * (k - 2))
print "Conforming plaintexts are between", hex(2 * B)[:10], "... and", hex(3 * B - 1)[:10], "...."



for i in range(2**19): # Like 8x coverage of 2**16 (two bytes)
    s0 = randint(2, 2**62) # not a Long int
    x = c * pow(s0, e, n) % n # multiplies plaintext by s0
    assert x < n
    found_s0 = oracle(x, privkey, Bits * 2)
    if i % 1000 == 0:
        print i
    if found_s0:
        break

print "success?", found_s0, s0


#### tests ####
short_message2 = "testing"
m2 = pkcs_1(short_message2, Bits)
c2 = rsa.encrypt_string(m2, pubkey)
assert oracle(c2, privkey, Bits)
warn("Passed assertions:", __file__)
