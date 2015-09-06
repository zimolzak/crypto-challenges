#!/usr/bin/env python

#     chal26.py - CBC when IV = Key
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
from Crypto.Cipher import AES

cipher = AES.new(key, AES.MODE_CBC)

#### tests, if any ####
warn("Passed assertions:", __file__)
