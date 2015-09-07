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

class BadCharacter(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return self.value

def check_ciphertext(ciphertext):
    key = open('unknown_key.txt', 'r').read().splitlines()[0]
    my_iv = key
    cipher = AES.new(key, AES.MODE_CBC, IV = my_iv)
    blocksize = 16
    plaintext = strip_padding(cipher.decrypt(my_iv + ciphertext)[blocksize:])
    for character in plaintext:
        if ord(character) > 127:
            raise BadCharacter(plaintext)
    if 'AUTHORIZED ADMIN' in plaintext:
        print "Server thinks that:" + plaintext
        return True
    else:
        print "Server thinks you are a normal user. Welcome!"
        return False

def get_keyiv_ciphertext():
    key = open('unknown_key.txt', 'r').read().splitlines()[0]
    my_iv = key
    cipher = AES.new(key, AES.MODE_CBC, IV = my_iv)
    blocksize = 16

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

    message = pad_multiple(message, blocksize)
    return cipher.encrypt(message)

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

def profile_token_cheat(cipher_nonce_list):
    ciphertext = cipher_nonce_list[0]
    nonce = cipher_nonce_list[1]
    return cryptopals.ctr(ciphertext, ctr_key, nonce, "little")

def site_profile_token(input_str):
    good_nonce = ""
    for i in range(8):
        good_nonce += chr(random.randint(0,255))
    input_str = input_str.replace(';', '.')
    input_str = input_str.replace('=', '.')
    plaintext = ('comment1=cooking%20MCs;userdata='
                 + input_str
                 + ';comment2=%20like%20a%20pound%20of%20bacon;')
    return [cryptopals.ctr(plaintext, ctr_key, good_nonce, "little")
            , good_nonce]
    # closure on ctr_key

def profile_is_admin(cipher_nonce_list):
    token = cipher_nonce_list[0]
    nonce = cipher_nonce_list[1]
    plaintext = cryptopals.ctr(token, ctr_key, nonce, "little")
    return ';admin=true;' in plaintext

def print_profile(profile):
    """Expects PROFILE to be a list, where the first element is the
    ciphertext we want to pretty-print. Probably the 2nd element is
    the nonce (discarded). Breaks ciphertext up into 32 bit words.
    """
    def hexord(x):
        return hex(ord(x))[2:]
    longstring = ''.join(map(hexord, profile[0]))
    word = ""
    for i in range(len(longstring)):
        word += longstring[i]
        if i % 8 == 7:
            print word,
            word = ''
    print


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
