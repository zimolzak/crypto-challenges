#!/usr/bin/env python

#     chal26.py - CTR bitflipping
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn, xor_str
from fakeserver import *
from math import ceil

adm_string = ";admin=true"
benign = site_profile_token("hello")
nice_try = site_profile_token(adm_string)

get_keystream = site_profile_token("\x00" * (len(adm_string) * 3))

#### Analysis starts here

print_profile(get_keystream)
print

ciphertext = get_keystream[0]
adm_per_cipher = int(len(ciphertext) / float(len(adm_string)))
for i in range(adm_per_cipher):
    head = "\x00" * i * len(adm_string)
    tail = "\x00" * (len(ciphertext) - (i+1) * len(adm_string))
    altered_ciphertext = xor_str(ciphertext, head+adm_string+tail)
    altered = [altered_ciphertext, get_keystream[1]]
    print_profile(altered)
    print profile_is_admin(altered)
    print

#### tests, if any ####
assert 'hello' in profile_token_cheat(benign)
assert not profile_is_admin(benign)
assert not profile_is_admin(nice_try)
warn("Passed assertions:", __file__)
