#!/usr/bin/env python

#     chal17.py - CBC padding oracle.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

import fakeserver
import cryptopals

[ciph, iv] = fakeserver.random_ciphertext_iv()

# my Plaintext 
# decrypt block C2 of ciphertext (up to N blocks):
#     my GG
#     increase bytes guessed (up to blocksize)
#         come up with guess g until server says valid
#             change bytes bbb at end of C1 to bbb ^ gGG ^ \x03\x03\x03
#             (valid is defined as: send [C1C2, iv])
#         prepend valid guess g onto the former GG to make GGG
#     append GGGGGGGGGGGGGGGG onto Plaintext

def xor(a,b):
    assert(len(a)==len(b))
    answer = ""
    for i in range(len(a)):
        answer = answer + chr((ord(a[i]) ^ ord(b[i])))
    return answer

assert xor('c', 'b') == "\x01"
assert xor('c', 'c') == "\x00"
assert xor('cb', 'cc') == "\x00\x01"


blocksize = 16 # too lazy to determine this now
plaintext = [""] * (len(ciph) / blocksize)
for blocknum in range(1, len(ciph) / blocksize): # note start w/ 1.
#    if blocknum > 2: #d
#        break #d
    Ca = ciph[blocksize*(blocknum-1) : blocksize*blocknum]
#    print len(Ca) #dm
#    print [Ca] #dm
#    print #dm
    Cb = ciph[blocksize*blocknum : blocksize*(blocknum+1)]
    for bytenum in range(blocksize):
        guess = ""
#        if bytenum > 1: #d
#            break #d
        for charnum in range(1,256): # wp sez start at \x01
            guess = chr(charnum)
            b = Ca[-(bytenum + 1):]
            g = guess + plaintext[blocknum] # p[b] will be incomplete
            x = chr(bytenum + 1) * (bytenum + 1)
            Cac = Ca[0:len(Ca)-(bytenum+1)] + xor(xor(b,g),x)
#            print [b, g, x] #dm
#            print [Cac] #dm
#            if charnum > 55: #d
#                break #d
            if fakeserver.padding_is_valid(Cac + Cb, iv):
                break
        plaintext[blocknum] = guess + plaintext[blocknum]

print plaintext[1:-1]

#### tests ####

for i in range(100):
    [ciph, iv] = fakeserver.random_ciphertext_iv()
    assert(fakeserver.padding_is_valid(ciph, iv))

cryptopals.warn("Passed assertions (" + __file__ + ")")
