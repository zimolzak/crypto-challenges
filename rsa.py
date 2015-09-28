#     rsa.py - Functions for implementation of RSA cryptosystem
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

import gensafeprime
import random
from cryptopals import warn

# Regarding gensafeprime: On OS X with Anaconda I had to do this [in
# addition to easy_install]:
# sudo ln -s /Users/ajz/anaconda/lib/libssl.1.0.0.dylib  /usr/lib
# sudo ln -s /Users/ajz/anaconda/lib/libcrypto.1.0.0.dylib /usr/lib

def extended_gcd(a, b):
    s = 0;    old_s = 1
    t = 1;    old_t = 0
    r = b;    old_r = a
    while r != 0:
        quotient = old_r / r
        (old_r, r) = (r, old_r - quotient * r)
        (old_s, s) = (s, old_s - quotient * s)
        (old_t, t) = (t, old_t - quotient * t)
    return {"B":[old_s, old_t], "G":old_r, "Q":[t, s]}

def invmod(a, m):
    D = extended_gcd(a,m)
    if D['G'] != 1:
        raise Exception("a and m are not coprime. "
                        + str(a) + " " + str(m) + " " + str(D['G']))
    ans = D['B'][0]
    if ans < 0:
        ans += m
    return ans

def keypair(bits):
    p = gensafeprime.generate(bits)
    q = gensafeprime.generate(bits)
    n = p * q
    et = (p-1) * (q-1)
    e = 3
    d = invmod(e, et)
    Public = [e, n]
    Private = [d, n]
    return [Public, Private]

def crypt(message, key):
    return pow(message, key[0], key[1])

def hexord(char):
    return hex(ord(char))[2:]

def s2i(string):
    """This is the cheesiest possible way I can think to do this."""
    hex_list = (map(hexord, string))
    for i, s in enumerate(hex_list):
        if len(s) == 1:
            hex_list[i] = '0' + s
        elif len(s) == 2:
            pass
        else:
            assert 0, "No such thing as 3-hex digit ASCII."
    return int('0x' + ''.join(hex_list), 16)

def i2s(integer):
    out = ""
    while integer:
        out += chr(integer & 0xff)
        integer = integer >> 8
    f = list(out)
    f.reverse()
    return ''.join(f)

def encrypt_string(string, public_key):
    integer = s2i(string)
    return crypt(integer, public_key)

def decrypt_string(ciphertext, private_key):
    return i2s(crypt(ciphertext, private_key))

#### tests ####

## invmod

assert invmod(17, 3120) == 2753

for i in range(10):
    a = gensafeprime.generate(64)
    m = gensafeprime.generate(64)
    x = invmod(a, m)
    assert (a*x) % m == 1

## i2s and s2i
    
h = 'Hiya'
assert i2s(s2i(h)) == h
assert s2i(i2s(999999999)) == 999999999
assert s2i(i2s(9999999999)) == 9999999999

## keypair and crypt

for i in range(10):
    U, R = keypair(64)
    msg = random.randint(1,10000)
    ciphertext = crypt(msg, U)
    decrypt = crypt(ciphertext, R)
    assert msg == decrypt

warn("Passed assertions:", __file__)
