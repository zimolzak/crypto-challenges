#!/usr/bin/env python

#     chal39.py - Implement RSA
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn

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

for i in gen_primes():
    if i > 1000:
        print i
        break

warn("Passed assertions:", __file__)
