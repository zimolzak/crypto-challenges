#     sha_analysis.py - Functions for analysis of SHA-1 Message
#     Authentication
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn, sha_fixated
import math

def restart_sha(hh, newmessage):
    h0 = (hh >> 128) & 0xffffffff
    h1 = (hh >> 96) & 0xffffffff
    h2 = (hh >> 64) & 0xffffffff
    h3 = (hh >> 32) & 0xffffffff
    h4 = hh & 0xffffffff
    return sha_fixated(newmessage, h0, h1, h2, h3, h4) #fixme

#### tests ####
warn("Passed assertions (" + __file__ + ")")
