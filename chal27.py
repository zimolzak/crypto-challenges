#!/usr/bin/env python

#     chal26.py - CBC when IV = Key
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn, pad_multiple, strip_padding, xor_str
from Crypto.Cipher import AES

key = open('unknown_key.txt', 'r').read().splitlines()[0]
my_iv = key
cipher = AES.new(key, AES.MODE_CBC, IV = my_iv)

message = """Don't call it a comeback
I've been here for years
I'm rocking my peers
Puttin' suckers in fear
Makin' the tears rain down like a monsoon
Listen to the bass go boom
Explosions, overpowerin'
Over the competition I'm towerin'
Wrecking shop when I write these lyrics
That'll make you call the cops
Don't you dare stare, you better move
Don't ever compare
Me to the rest that'll all get sliced and diced
Competition's payin' the price
"""

blocksize = 16
message = pad_multiple(message, blocksize)
ciphertext = cipher.encrypt(message)
decrypted = strip_padding(cipher.decrypt(my_iv + ciphertext)[blocksize:])

#### Analysis

c0 = ciphertext[0:blocksize]
c4_end = ciphertext[4 * blocksize : ]
mod_ciphertext = c0 + ("\x00" * blocksize) + c0 + c4_end
mod_decrypt = strip_padding(cipher.decrypt(my_iv + mod_ciphertext)[blocksize:])

p0 = mod_decrypt[0:blocksize]
p2 = mod_decrypt[2*blocksize : 3*blocksize]
key_recovered = xor_str(p0, p2)
print "Found that key is", key_recovered
print

att_cipher = AES.new(key_recovered, AES.MODE_CBC, IV = key_recovered)

admin = """
     THE BEARER OF THIS TOKEN IS A GENUINE AND AUTHORIZED ADMIN.
                      So please Treat Ver Right.
                            GOOD FOREVER.
"""

admin = pad_multiple(admin,blocksize)
att_ctext = att_cipher.encrypt(admin)
print ("Server thinks that:" +
       strip_padding(cipher.decrypt(key_recovered + att_ctext)[blocksize:]))

#### tests, if any ####
assert decrypted[:50] == message[:50]
assert key_recovered == key
warn("Passed assertions:", __file__)
