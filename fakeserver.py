#     fakeserver.py - Simulate "friendly" server functions that can be
#     analyzed using CBC padding, or random access read/write CTR.
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

#### CTR

ecb_encrypted = base64.b64decode(''.join(open('25.txt', 'r').
                                         read().splitlines()))
plain = AES.new("YELLOW SUBMARINE", AES.MODE_ECB).decrypt(ecb_encrypted)
ctr_key = open('unknown_key.txt', 'r').read().splitlines()[0]
ctr_nonce = ""
for i in range(8):
    # I believe this sets it upon import of this file, not for each
    # encrypt/decrypt. Not the most secure, but in any case I don't
    # use a nonce attack to "cheat" at CTR challenges.
    ctr_nonce += chr(random.randint(0,255))

ctr_ciphertext = cryptopals.ctr(plain, ctr_key, ctr_nonce, "little")

def edit(ciphertext, key, nonce, offset, newtext):
    plaintext = cryptopals.ctr(ciphertext, key, nonce, "little")
    nchars = len(newtext)
    plaintext = plaintext[0:offset] + newtext + plaintext[offset+nchars:]
    return cryptopals.ctr(plaintext, key, nonce, "little")

def edit_public(ciphertext, offset, newtext):
    # closure
    return edit(ciphertext, ctr_key, ctr_nonce, offset, newtext)

def ctr_cheat(ciphertext):
    return cryptopals.ctr(ciphertext, ctr_key, ctr_nonce, "little")

def site_profile_token(input_str):
    input_str = input_str.replace(';', '.')
    input_str = input_str.replace('=', '.')
    plaintext = ('comment1=cooking%20MCs;userdata='
                 + input_str
                 + ';comment2=%20like%20a%20pound%20of%20bacon;')
    # closure
    return cryptopals.ctr(plaintext, ctr_key, ctr_nonce, "little")

def profile_is_admin(token):
    plaintext = cryptopals.ctr(token, ctr_key, ctr_nonce, "little")
    return ';admin=true;' in plaintext

#### tests, CTR ####

assert len(ctr_nonce)==8
assert len(ctr_ciphertext) == len(plain)
assert plain.splitlines()[9] == "To just let it flow, let my concepts go "
cryptopals.warn("Passed assertions:", __file__)

#### tests ####

_plaintext = "YELLOW SUB"
_key = open('unknown_key.txt', 'r').read().splitlines()[0]
_plaintext = pad_multiple(_plaintext, AES.block_size)
_iv = Random.new().read(AES.block_size)
_cipher = AES.new(_key, AES.MODE_CBC, _iv)
_ciphertext = _cipher.encrypt(_plaintext)

assert(padding_is_valid(_ciphertext, _iv))

_plaintext = "YELLOW SUBMAR\x04\x04\x04"
_key = open('unknown_key.txt', 'r').read().splitlines()[0]
# Note that we skip the padding in order to give this _plaintext bad padding.
_iv = Random.new().read(AES.block_size)
_cipher = AES.new(_key, AES.MODE_CBC, _iv)
_ciphertext = _cipher.encrypt(_plaintext)

assert(not padding_is_valid(_ciphertext, _iv))

cryptopals.warn("Passed assertions (" + __file__ + ")")
