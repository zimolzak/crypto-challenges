#!/usr/bin/env python

#     chal30.py - Break a secret prefix MD4 MAC (length extension).
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn, unknown_key as key
from py_md4.md4 import md4, md4_padding, restart_md4
import math

message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
auth_code_str = md4(key + message)
print "Message                           ", message
print "Auth code for Message:            ", auth_code_str
print "Story checks out?                 ", auth_code_str == md4(key + message)
print

#### Mallory starts here

# Construct a new message.
keylen_guess = 16 # Need perfect guess to get perfect glue.
fake_byte_array = [ord(c) for c in ("A" * keylen_guess) + message]
glue_guess = ''.join(map(chr, md4_padding(fake_byte_array, 0)))
adm = ";admin=true"
new_message = message + glue_guess + adm
print "New message                       ", new_message

# Construct the MAC for that message.
KOG_len_guess = int(math.ceil((keylen_guess + len(message)) / 64.0)) * 64
  # Len of key+original+glue
print "Key + original + glue length =    ", KOG_len_guess
new_auth_code_str = restart_md4(auth_code_str, adm, KOG_len_guess)
print "Guessed auth code for new message ", new_auth_code_str

# Check the constructed MAC.
i_am_a_winner = (new_auth_code_str == md4(key + new_message))
print "Story checks out?                 ", i_am_a_winner
print
print "New Message (with unprintables)", [new_message]
print

#### tests, if any ####
assert i_am_a_winner
warn("Passed assertions:", __file__)
