#     fakeserver.py - Simulate "friendly" server functions that can be
#     analyzed using CBC padding.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

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
    except cryptopals.BadPaddingChar as err:
        return False
    except cryptopals.MisplacedPaddingChar as err:
        return False
    else:
        return True

#### tests ####


plaintext = "Hello world"
key = open('unknown_key.txt', 'r').read().splitlines()[0]
plaintext = pad_multiple(plaintext, AES.block_size)
iv = Random.new().read(AES.block_size)
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(plaintext)

assert(padding_is_valid(ciphertext, iv))

plaintext = "Hello \x03 world"
key = open('unknown_key.txt', 'r').read().splitlines()[0]
plaintext = pad_multiple(plaintext, AES.block_size)
iv = Random.new().read(AES.block_size)
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(plaintext)

assert(not padding_is_valid(ciphertext, iv))
