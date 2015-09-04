#!/usr/bin/env python

#     chal24.py - Make a MT13397 stream cipher and analyze.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn, xor_str
import myrand
import random
from time import time, ctime, strptime, mktime

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

s = random.choice([int(time()), 4242])

url = "https://www.bozofarm.com/acct/pwrst?token=" + get_token(s)

print url
print

# check if any given password token is actually the product of an
# MT19937 PRNG seeded with the current time.

def url_is_time_seeded(url, when):
    start = url.find('token=') + len('token=')
    token_hex = url[start : start + 8] # 8 hex char = 32 bit
    num = int(token_hex, base=16)
    try:
        s = myrand.find_time_seed(num, when)
    except myrand.NoTimeSeed:
        return False
    else:
        return s

urls = [url,
        '?token=7d8bb0e5fbfc417aa7f9132a11182d82',
        'token=f4c7765d7af043ae9ffa16d89357663f',
        'token=dada53bc868a0308bf93',
        'token=2364db032587e3473342',
        'token=dbad1e77cbc961a31448']

times = [int(time()),
         int(mktime(strptime('Thu Jul 30 20:20:00 2015'))),
         int(mktime(strptime('Thu Apr  2 19:17:00 2015'))),
         int(mktime(strptime('Mon Feb 23 19:06:00 2015'))),
         int(mktime(strptime('Mon Feb 19 13:08:00 2015'))),
         int(mktime(strptime('Mon Feb  9 08:27:00 2015')))]

for i in range(len(urls)):
    ts =  url_is_time_seeded(urls[i], times[i])
    if ts:
        print "Seed", ts, "found, meaning", ctime(ts)
    else:
        print "Not time seeded"

#### tests, if any ####
assert decipher == plaintext
assert winning_decrypt == plaintext
warn("Passed assertions:", __file__)
