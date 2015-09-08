#     sha_analysis.py - Functions for analysis of SHA-1 Message
#     Authentication
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn, sha_fixated
import math

def restart_sha(hh, newmessage, extra_len):
    """Add arbitrary data to a SHA-signed message, and make it look like
    it was signed by the same key as the original message.

    In brief, perform length extension attack on SHA-1. Given hh =
    SHA1(key+original+pad1), and a guess at length of
    key+original+pad1, return SHA1(key+message+pad1+newmessage+pad2).
    In other words, add data and produce valid signature without
    knowing the key. Assumption: recipient doesn't care that there are
    weird pad1 characters in the middle of what sender claims is the
    message.

    HH is the hash of the previous message as a (usually rather big)
    integer. Should be decomposable into exactly five 32-bit words.
    Newmessage is what you want to add.

    Extra_Len is a guess, in bytes, at len(key+original+pad1). Should
    be multiple of 64 bytes. This amounts to a guess at the length of
    the key within about a 64-byte range (because len(message) is
    known and padding always gets it to multiple of 64). *Outside* of
    this function you will have to guess key length *exactly*, in
    order to guess pad1 exactly and generate the supposed signed
    message.
    """
    h0 = (hh >> 128) & 0xffffffff
    h1 = (hh >> 96) & 0xffffffff
    h2 = (hh >> 64) & 0xffffffff
    h3 = (hh >> 32) & 0xffffffff
    h4 = hh & 0xffffffff
    return sha_fixated(newmessage, h0, h1, h2, h3, h4, extra_len)

#### tests ####
warn("Passed assertions (" + __file__ + ")")
