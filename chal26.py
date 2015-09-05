#!/usr/bin/env python

#     chal26.py - CTR bitflipping
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
from fakeserver import site_profile_token, profile_is_admin, ctr_cheat

benign = site_profile_token("hello")
nice_try = site_profile_token(";admin=true")

#### tests, if any ####
assert 'hello' in ctr_cheat(benign)
assert not profile_is_admin(benign)
assert not profile_is_admin(nice_try)
warn("Passed assertions:", __file__)
