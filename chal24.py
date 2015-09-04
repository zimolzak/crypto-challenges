#!/usr/bin/env python

#     chal24.py - Make a MT13397 stream cipher and analyze.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn, xor_str
import myrand
import random
import time

#### Construct a plaintext

letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
plaintext = ''
for i in range(random.randint(1,20)):
    plaintext += random.choice(letters)
plaintext += 'A' * 14
print "plaintext", plaintext

#### Encrypt it and test decryption.

def msc(text, seed):
    """Mersenne stream cipher"""
    assert seed < 2**16
    rng = myrand.MTRNG(seed)
    output = ""
    num = 0
    for text_char in text:
        if num == 0:
            num = rng.extract_number() # get a new 4 bytes
        keystream_num = num & 0xff # one byte at a time
        num = num >> 8
        output += chr(keystream_num ^ ord(text_char))
    return output

key = random.randint(0,65535)

key = 2100 # Uncomment me if you want it to go fast but cheating.

ciphertext = msc(plaintext, key)
decipher = msc(ciphertext, key)
print "test of decryption yields", decipher

#### Brute-force the encryption 

winning_key = 0
for keytry in range(65536):
    # Seems to brute-force 1000 per 3 sec. Worst case 3.28 min.
    decipher_try = msc(ciphertext, keytry)
    if keytry % 1000 == 0:
        print keytry
    if decipher_try[-14:] == "A" * 14:
        print "Broken with key", keytry
        winning_key = keytry
        break

winning_decrypt = msc(ciphertext, winning_key)
print "broken as", winning_decrypt

#### Generate a random "password reset token" using MT19937 seeded
#### from the current time.

def hexchop(n):
    return hex(n)[2:]

def get_token(seed):
    rng = myrand.MTRNG(seed)
    numbers = []
    for i in range(4):
        # 4 bytes per iter * 4 iter = 16 byte token.
        numbers += [rng.extract_number()]
    return ''.join(map(hexchop, numbers))

print """
Click here to reset your password. If you cannot click the link,
then paste it into your browser. If you did not request a password
reset, contact the system administrator.
"""

s = random.choice([int(time.time()), 4242])

url = "https://www.bozofarm.com/acct/pwrst?token=" + get_token(s)

print url
print

# check if any given password token is actually the product of an
# MT19937 PRNG seeded with the current time.

def url_is_time_seeded(url):
    start = url.find('token=') + len('token=')
    token_hex = url[start : start + 8] # 8 hex char = 32 bit
    num = int(token_hex, base=16)
    try:
        s = myrand.find_time_seed(num)
    except myrand.NoTimeSeed:
        return False
    else:
        return s

ts =  url_is_time_seeded(url)
if ts:
    print "Seed", ts, "found, meaning", time.ctime(ts)
else:
    print "Not time seeded"

#### tests, if any ####
assert decipher == plaintext
assert winning_decrypt == plaintext
warn("Passed assertions:", __file__)
