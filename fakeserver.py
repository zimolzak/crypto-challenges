#     fakeserver.py - Simulate "friendly" server functions that can be
#     analyzed using CBC padding.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

import random
import base64
from cryptopals import pad_multiple
from Crypto import Random
from Crypto.Cipher import AES

def random_ciphertext_iv():
    blocksize = 16
    plaintext = base64.b64decode(random.choice(
        open('17.txt', 'r').read().splitlines()
    ))
    key = open('unknown_key.txt', 'r').read().splitlines()[0]
    plaintext = pad_multiple(plaintext, AES.block_size)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return [cipher.encrypt(plaintext), iv]

# def padding_is_valid(ciphertext, iv):
