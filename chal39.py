#!/usr/bin/env python

#     chal39.py - Implement RSA
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
import random

def gen_primes():
    """ Generate an infinite sequence of prime numbers.
    by David Eppstein, UC Irvine, 28 Feb 2002
    """
    D = {}
    q = 2
    while True:
        if q not in D:
            yield q
            D[q * q] = [q]
        else:
            for p in D[q]:
                D.setdefault(p + q, []).append(p)
            del D[q]
        q += 1

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

def prime_greater(x):
    for i in gen_primes():
        if i > x:
            return i

def keypair(maximum):
    p = prime_greater(random.randint(2,maximum))
    q = prime_greater(random.randint(2,maximum))
    n = p * q
    et = (p-1) * (q-1)
    for test in gen_primes():
        E = extended_gcd(test, et)
        if E['G'] == 1:
            e = test # I really think e can't always be 3.
            break
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
    return int('0x' + ''.join((map(hexord, string))), 16)

def i2s(integer):
    out = ""
    while integer:
        out += chr(integer & 0xff)
        integer = integer >> 8
    f = list(out)
    f.reverse()
    return ''.join(f)

hello = 'Hiya'
integer = s2i(hello)
print integer
string = i2s(integer)
print string

U, R = keypair(10 ** 5)
ciphertext = crypt(integer, U)
print ciphertext
decrypt = crypt(ciphertext, R)
print decrypt
print "The answer is", i2s(decrypt)
assert hello == i2s(decrypt)

#### tests ####
for i in range(20):
    U, R = keypair(10 ** 5)
    msg = random.randint(1,10000)
    ciphertext = crypt(msg, U)
    decrypt = crypt(ciphertext, R)
    print "The answer is", decrypt
    assert msg == decrypt

for i in range(20):
    a = prime_greater(random.randint(2,100000))
    m = prime_greater(random.randint(2,100000))
    x = invmod(a, m)
    assert (a*x) % m == 1

assert prime_greater(1000) == 1009
assert invmod(17, 3120) == 2753
warn("Passed assertions:", __file__)
