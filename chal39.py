#!/usr/bin/env python

#     chal39.py - Implement RSA
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
import rsa

# On OS X with Anaconda I had to do this [in addition to easy_install]:
# sudo ln -s /Users/ajz/anaconda/lib/libssl.1.0.0.dylib  /usr/lib
# sudo ln -s /Users/ajz/anaconda/lib/libcrypto.1.0.0.dylib /usr/lib

hello = 'Hello, world! This is a message from me to you! I am typing this on a certain type of computer, and I wonder how many bits I will need.'

bits = len(hello) * 8 / 2
print bits, "bit key"
U, R = rsa.keypair(bits)
ciphertext = rsa.encrypt_string(hello, U)
decrypt = rsa.decrypt_string(ciphertext, R)
print "Decrypted this message:", decrypt
assert hello == decrypt

#### tests ####

warn("Passed assertions:", __file__)
