#!/usr/bin/env python

#     chal17.py - CBC padding oracle.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

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

blocksize = 16 # too lazy to determine this now
plaintext = [""] * (len(ciph) / blocksize)
for blocknum in range(len(ciph) / blocksize):
    if blocknum == 0:
        Ca = iv # There is smarter way, without the IF.
    else:
        Ca = ciph[blocksize*(blocknum-1) : blocksize*blocknum]
    Cb = ciph[blocksize*blocknum : blocksize*(blocknum+1)]
    for n_bytes in range(1, blocksize+1): 
        guess = ""
        for charnum in range(2,256): # Might be screwed if it is \x01
            guess = chr(charnum)
            b = Ca[-(n_bytes):]
            g = guess + plaintext[blocknum] # p[b] will be incomplete
            x = chr(n_bytes) * (n_bytes)
            Cac = Ca[:-(n_bytes)] + cryptopals.xor_str(
                cryptopals.xor_str(b,g),x)
            if fakeserver.padding_is_valid(Cac + Cb, iv):
                break
        plaintext[blocknum] = guess + plaintext[blocknum]

output = cryptopals.strip_padding(''.join(plaintext))
print output

#### tests ####
assert(cryptopals.strip_padding(fakeserver.cheat(ciph,iv)) == output)

for i in range(100):
    [ciph, iv] = fakeserver.random_ciphertext_iv()
    assert(fakeserver.padding_is_valid(ciph, iv))

cryptopals.warn("Passed assertions (" + __file__ + ")")
