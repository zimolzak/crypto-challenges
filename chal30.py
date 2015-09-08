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
print "Message                          ", message
print "Auth code for Message:           ", auth_code_str
print "Story checks out?                ", auth_code_str == md4(key + message)
print

# wish list: md4_padding, restart_md4

#### Mallory starts here

# Construct a new message.
keylen_guess = 16 # Need perfect guess to get perfect glue.
fake_byte_array = [ord(c) for c in ("A" * keylen_guess) + message]
glue_guess_array = md4_padding(fake_byte_array, 0)
glue_guess = ""
for n in glue_guess_array:
    glue_guess += chr(n)
adm = ";admin=true"
new_message = message + glue_guess + adm
print "New message                      ", new_message

#delete next block
print
print 'lm', len(message)
print "lnm", len(new_message)
print

# Construct the MAC for that message.
KOG_len_guess = int(math.ceil((keylen_guess + len(message)) / 64.0)) * 64
  # Len of key+original+glue
print "Key + original + glue length =   ", KOG_len_guess
auth_code = int(auth_code_str, 16)
new_auth_code = restart_md4(auth_code, adm, KOG_len_guess, debug=True)
print "Guessed auth code for new message", new_auth_code
print "cheat                            ", md4(key + new_message, debug=True) #deleteme

# Check the constructed MAC.
i_am_a_winner = (new_auth_code == md4(key + new_message))
print "Story checks out?                ", i_am_a_winner
print
print "New Message (with unprintables)", [new_message]
print

#### tests, if any ####
assert i_am_a_winner
warn("Passed assertions:", __file__)
