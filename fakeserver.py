#     fakeserver.py - Simulate "friendly" server functions that can be
#     analyzed using CBC padding.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

import random
import base64
from cryptopals import pad_multiple, strip_padding
import cryptopals
from Crypto import Random
from Crypto.Cipher import AES

def random_ciphertext_iv():
    plaintext = base64.b64decode(random.choice(
        open('17.txt', 'r').read().splitlines()
    ))
    key = open('unknown_key.txt', 'r').read().splitlines()[0]
    plaintext = pad_multiple(plaintext, AES.block_size)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return [cipher.encrypt(plaintext), iv]

def padding_is_valid(ciphertext, iv):
    key = open('unknown_key.txt', 'r').read().splitlines()[0]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    try:
        x = (strip_padding(plaintext))
    except cryptopals.BadPadding as err:
        return False
    else:
        return True

def cheat(ciphertext, iv):
    key = open('unknown_key.txt', 'r').read().splitlines()[0]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(ciphertext)

#### tests ####

plaintext = "YELLOW SUB"
key = open('unknown_key.txt', 'r').read().splitlines()[0]
plaintext = pad_multiple(plaintext, AES.block_size)
iv = Random.new().read(AES.block_size)
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(plaintext)

assert(padding_is_valid(ciphertext, iv))

plaintext = "YELLOW SUBMAR\x04\x04\x04"
key = open('unknown_key.txt', 'r').read().splitlines()[0]
# Note that we skip the padding in order to give this plaintext bad padding.
iv = Random.new().read(AES.block_size)
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(plaintext)

assert(not padding_is_valid(ciphertext, iv))

cryptopals.warn("Passed assertions (" + __file__ + ")")
