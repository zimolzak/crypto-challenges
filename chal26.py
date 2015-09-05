#!/usr/bin/env python

#     chal26.py - CTR bitflipping
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn, xor_str
from fakeserver import *

adm_string = ";admin=true"
benign = site_profile_token("hello")
nice_try = site_profile_token(adm_string)

#### Analysis starts here

get_keystream = site_profile_token("\x00" * (len(adm_string)))
ciphertext = get_keystream[0]
altered = []
for i in range(len(ciphertext) - len(adm_string)):
    head = "\x00" * i
    tail = "\x00" * (len(ciphertext) - i - len(adm_string))
    altered_ciphertext = xor_str(ciphertext, head+adm_string+tail)
    altered = [altered_ciphertext, get_keystream[1]]
    if profile_is_admin(altered):
        print "Success at offset", i
        break

if len(altered) > 0:
    print "Success with the following ciphertext:"
    print_profile(altered)
    print "Decrypts to:"
    print profile_token_cheat(altered)

#### tests, if any ####
assert len(altered) > 0
assert profile_is_admin(altered)
assert 'hello' in profile_token_cheat(benign)
assert not profile_is_admin(benign)
assert not profile_is_admin(nice_try)
warn("Passed assertions:", __file__)
