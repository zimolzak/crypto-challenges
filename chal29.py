#!/usr/bin/env python

#     chal29.py - Break a secret prefix SHA-1 MAC (length extension).
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import (warn, sha1, sha_padding, i2h, unknown_key as key)
from sha_analysis import restart_sha
import math

message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
auth_code = sha1(key + message)
print "Message                           ", message
print "Auth code for Message:            ", i2h(auth_code)
print "Story checks out?                 ", auth_code == sha1(key + message) 
print

#### Mallory starts here

# Construct a new message.
keylen_guess = 16 # Need perfect guess to get perfect glue.
glue_guess = sha_padding(("A" * keylen_guess) +  message, 0)
adm = ";admin=true"
new_message = message + glue_guess + adm
print "New message                       ", new_message

# Construct the MAC for that message.
KOG_len_guess = int(math.ceil((keylen_guess + len(message)) / 64.0)) * 64
  # Len of key+original+glue
print "Key + original + glue length =    ", KOG_len_guess
new_auth_code = restart_sha(auth_code, adm, KOG_len_guess)
print "Guessed auth code for new message ", i2h(new_auth_code)

# Check the constructed MAC.
i_am_a_winner = (new_auth_code == sha1(key + new_message))
print "Story checks out?                 ", i_am_a_winner
print
print "New Message (with unprintables)", [new_message]
print

#### tests, if any ####
assert i_am_a_winner
warn("Passed assertions:", __file__)
