#!/usr/bin/env python

#     chal47.py - RSA padding oracle, simple.
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
import rsa
from interval import simplify
import pdb
from time import time

def ceildiv(x, y):
    if x % y == 0:
        return x / y
    else:
        return x / y + 1

def pkcs_1(string, bits):
    """Pad a string to specified number of bits.

    Start with 0x0002, then a bunch of 0xFF, then 0x00, then the
    string. Not to be confused with a slightly different function I
    wrote called pkcs_1_5().
    """
    assert bits % 8 == 0
    byte_goal = bits / 8
    assert len(string) <= byte_goal - 3
    prepend = "\x00\x02"
    append = "\x00"
    bytes_to_add = (byte_goal -
                    (len(string) % byte_goal) -
                    len(prepend) -
                    len(append))
    return prepend + ("\xff" * bytes_to_add) + append + string

def oracle(ciphertext, privkey, bits):
    """bits should equal the max bits of a message, not bit length of
    key.
    """
    plaintext = rsa.decrypt_string(ciphertext, privkey)
    assert bits % 8 == 0
    bytes = bits / 8
    diff = bytes - len(plaintext)
    plaintext = "\x00" * diff + plaintext
    assert len(plaintext) == bytes, len(plaintext)
    return plaintext[0] == "\x00" and plaintext[1] == "\x02"

Bits = 768 / 2
pubkey, privkey = rsa.keypair(Bits)
print pubkey[1].bit_length(), "bit modulus"
short_message = """Now these points of data make a beautiful line
And we're out of beta; we're releasing on time"""

m = pkcs_1(short_message, Bits * 2) # Bits*2 = length of n
c = rsa.encrypt_string(m, pubkey)
print "Oracle says that raw ciphertext conforms?", oracle(c, privkey, Bits * 2)
assert oracle(c, privkey, Bits*2)

#### Step 1 (Easy if c is already PKCS conforming)
e = pubkey[0]
n = pubkey[1]
k = Bits * 2 / 8 # Length of n in bytes
B = 2 ** (8 * (k - 2))
s = [1]
c = [c]
M = [[[2*B, 3*B-1]]] # M is a list of sets of intervals.
i = 1

start = time()
while(1):
    #### Step 2
    if i == 1:
        s.append(ceildiv(n , (3 * B))) # will increment
        print "step 2a (sometimes takes a while)"
    elif i > 1 and len(M[i-1]) >= 2:
        s.append(s[i-1] + 1) # will increment
    if i == 1 or (i > 1 and len(M[i-1]) >= 2):
        while s[i] < n:
            x = c[0] * pow(s[i], e, n) % n # multiplies plaintext_0 by s[i]
            if oracle(x, privkey, Bits * 2):
                break
            s[i] += 1
            if s[i] % 1000 == 0:
                now = time()
                Q = s[i] - ceildiv(n , (3 * B))
                print "  ", s[i], Q, '/', round(now - start, 1), '=', round(Q/(now - start), 1)
        print "i=", i,
    elif len(M[i-1]) == 1:
        a, b = M[i-1][0]
        r = ceildiv(2 * (b*s[i-1] - 2*B) , n) # will increment
        conforming = False
        s.append(None) # need to create a slot for s[i]
        while not conforming:
            sLow = ceildiv(2*B + r*n, b)
            sHigh = ceildiv(3*B + r*n,  a)
            s[i] = sLow # will increment
            while s[i] <= sHigh: # tricky ceil and < vs <=
                x = c[0] * pow(s[i], e, n) % n # multiplies plaintext_0 by s[i]
                if oracle(x, privkey, Bits * 2):
                    conforming = True # breaks out of both while loops
                    break
                s[i] += 1
            r += 1
        if i % 20 == 0:
            print "i=", i,

    #### Step 3
    m_set = []
    for a, b in M[i-1]:
        rlow = ceildiv(a * s[i] - 3*B + 1, n)
        rhigh = (b * s[i] - 2*B) // n
        if rlow > rhigh:
            continue
        assert rlow <= rhigh, [a, b, rlow, rhigh]
        for r in range(rlow, rhigh+1):
            mlow = max(a, ceildiv(2*B + r*n, s[i]))
            mhigh =  min(b, (3*B - 1 + r*n) // s[i])
            assert mlow <= mhigh, [mlow, mhigh, mlow - a, b - mhigh,
                                   rlow, rhigh, r]
            this_interval = [mlow, mhigh]
            if this_interval not in m_set:
                m_set.append(this_interval)
        M.append(simplify(m_set))
    
    #### Step 4
    if len(M[i]) == 1 and M[i][0][0] == M[i][0][1]:
        a = M[i][0][0]
        m = a * rsa.invmod(s[0], n) % n
        print
        print
        print "Hooray! m=", m
        result = rsa.i2s(m)
        print "i2s=", [result]
        break
    else:
        if len(M[i]) > 1:
            print "Iterate because len", len(M[i])
        else:
            if i % 20 == 0:
                print "Iterate because interval > 0"
        i += 1

#### tests ####
nc = len(short_message)
assert result[-nc:] == short_message
short_message2 = "du"
m2 = pkcs_1(short_message2, Bits*2)
c2 = rsa.encrypt_string(m2, pubkey)
assert oracle(c2, privkey, Bits*2)
warn("Passed assertions:", __file__)
