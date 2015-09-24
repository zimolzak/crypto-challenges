#!/usr/bin/env python

#     chal39.py - Implement RSA
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
import random
import numpy
import gensafeprime
from math import log, ceil

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

def primesfrom2to(n):
    # http://stackoverflow.com/questions/2068372/fastest-way-to-list-all-primes-below-n-in-python/3035188#3035188
    """ Input n>=6, Returns a array of primes, 2 <= p < n """
    sieve = numpy.ones(n/3 + (n%6==2), dtype=numpy.bool)
    sieve[0] = False
    for i in xrange(int(n**0.5)/3+1):
        if sieve[i]:
            k=3*i+1|1
            sieve[      ((k*k)/3)      ::2*k] = False
            sieve[(k*k+4*k-2*k*(i&1))/3::2*k] = False
    return numpy.r_[2,3,((3*numpy.nonzero(sieve)[0]+1)|1)]

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

def rwh_primes2(n):
    # http://stackoverflow.com/questions/2068372/fastest-way-to-list-all-primes-below-n-in-python/3035188#3035188
    """ Input n>=6, Returns a list of primes, 2 <= p < n """
    correction = (n%6>1)
    n = {0:n,1:n-1,2:n+4,3:n+3,4:n+2,5:n+1}[n%6]
    sieve = [True] * (n/3)
    sieve[0] = False
    for i in xrange(int(n**0.5)/3+1):
      if sieve[i]:
        k=3*i+1|1
        sieve[      ((k*k)/3)      ::2*k]=[False]*((n/6-(k*k)/6-1)/k+1)
        sieve[(k*k+4*k-2*k*(i&1))/3::2*k]=[False]*((n/6-(k*k+4*k-2*k*(i&1))/6-1)/k+1)
    return [2,3] + [3*i+1|1 for i in xrange(1,n/3-correction) if sieve[i]]

def prime_greater(x):
#### Numpy
#    return primesfrom2to(x)[-1]
#### Standard
#    for i in gen_primes():
#        if i > x:
#            return i
#### RWH
#    return rwh_primes2(x)[-1]
    bits = int(ceil(log(x) / log(2)))
    return gensafeprime.generate(bits)

def keypair(maximum):
    p = prime_greater(maximum)
    q = prime_greater(maximum)
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

print prime_greater(10 ** 10)
    
hello = 'Hiya'
integer = s2i(hello)
U, R = keypair(10 ** 5)
ciphertext = crypt(integer, U)
decrypt = i2s(crypt(ciphertext, R))
print "Decrypted this message:", decrypt
assert hello == decrypt

#### tests ####
h = 'Hiya'
assert i2s(s2i(h)) == h

for i in range(10):
    U, R = keypair(10 ** 5)
    msg = random.randint(1,10000)
    ciphertext = crypt(msg, U)
    decrypt = crypt(ciphertext, R)
    assert msg == decrypt

for i in range(10):
    a = prime_greater(random.randint(2,100000))
    m = prime_greater(random.randint(2,100000))
    x = invmod(a, m)
    assert (a*x) % m == 1

assert invmod(17, 3120) == 2753
warn("Passed assertions:", __file__)
