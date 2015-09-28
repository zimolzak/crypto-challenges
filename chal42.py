#!/usr/bin/env python

#     chal42.py - e=3 RSA
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
import rsa

message = 'Blah blah'
bits = len(message) * 8 / 2
U, R = rsa.keypair(bits)
ciphertext = rsa.encrypt_string(message, U)
decrypt = rsa.decrypt_string(ciphertext, R)
print "Decrypted this:", decrypt
print

m2 = 0x0002
c2 = rsa.crypt(m2, U)
print "The block", m2, "encrypts in e=3 RSA to", c2
d2 = rsa.crypt(c2, R)
print "Decrypted this:", d2

#### tests ####
assert message == decrypt
assert d2 == m2
warn("Passed assertions:", __file__)
