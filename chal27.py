#!/usr/bin/env python

#     chal26.py - CBC when IV = Key
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn, strip_padding, xor_str, pad_multiple
from fakeserver import check_ciphertext, get_keyiv_ciphertext, BadCharacter
from Crypto.Cipher import AES

print "==== Setup ===="
ciphertext = get_keyiv_ciphertext()
untainted_is_admin = check_ciphertext(ciphertext)

#### Analysis

print
print "==== Analysis ===="

blocksize = 16
c0 = ciphertext[0:blocksize]
c4_end = ciphertext[4 * blocksize : ]
mod_ciphertext = c0 + ("\x00" * blocksize) + c0 + c4_end

try:
    check_ciphertext(mod_ciphertext)
except BadCharacter as badchar_obj:
    mod_decrypt = str(badchar_obj)
    p0 = mod_decrypt[0:blocksize]
    p2 = mod_decrypt[2*blocksize : 3*blocksize]
    key_recovered = xor_str(p0, p2)
    print "Found that key is", key_recovered

att_cipher = AES.new(key_recovered, AES.MODE_CBC, IV = key_recovered)

admin = """
     THE BEARER OF THIS TOKEN IS A GENUINE AND AUTHORIZED ADMIN.
                      So please Treat Ver Right.
                            GOOD FOREVER.
"""

admin = pad_multiple(admin,blocksize)
att_ctext = att_cipher.encrypt(admin)
modified_is_admin = check_ciphertext(att_ctext)

#### tests, if any ####
key = open('unknown_key.txt', 'r').read().splitlines()[0]
assert key_recovered == key
assert not untainted_is_admin
assert modified_is_admin
warn("Passed assertions:", __file__)
