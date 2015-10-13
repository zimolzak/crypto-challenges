#!/usr/bin/env python

#     chal47.py - RSA padding oracle, simple.
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
import rsa
from random import randint
from time import time
import math

def ceildiv(x, y):
    if x % y == 0:
        return x / y
    else:
        return x / y + 1

def pkcs_1(string, bits):
    """Pad a string to specified number of bits.

    Start with 0x0001, then a bunch of 0xFF, then 0x00, then the
    string. Not to be confused with a slightly different function I
    wrote called pkcs_1_5().
    """
    assert len(string) < 256
    assert bits % 8 == 0
    byte_goal = bits / 8
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

Bits = 256

#pubkey, privkey = rsa.keypair(Bits)

# Set to two static keys known to yield a low s1, for efficiency's
# sake while testing. FIXME - delete these two static values maybe,
# and reinstitute random keypair generation?

pubkey = [3, 9735206716434150621826121115776169484354439000548572013769499204551711882059896149904093367744988308059944044877240224792294074570476059825549758422564041]

privkey = [6490137810956100414550747410517446322902959333699048009179666136367807921373131849354707838340464847438729993288283438687391902142174646364993310402589795, 9735206716434150621826121115776169484354439000548572013769499204551711882059896149904093367744988308059944044877240224792294074570476059825549758422564041]

short_message = "kick it, CC"
m = pkcs_1(short_message, Bits * 2) # Bits*2 = length of n
c = rsa.encrypt_string(m, pubkey)

print "Oracle says that raw ciphertext conforms?", oracle(c, privkey, Bits * 2)

#### Step 1. Can be skipped if c is already PKCS conforming

e = pubkey[0]
n = pubkey[1]
k = Bits * 2 / 8 # Length of n in bytes
B = 2 ** (8 * (k - 2))
print "Conforming plaintexts are between", hex(2 * B)[:10], "... and", hex(3 * B - 1)[:10], "...."
print

assert oracle(c, privkey, Bits*2)
s = [1]
c = [c]
# M is a list of sets of intervals.
M = [[[2*B, 3*B-1]]]
i = 1
start = time()

while(1):
    #### Step 2
    if i == 1:
        #print "Step 2.a"
        s.append(int(n / (3 * B))) # Set s[1]. Don't use range() or it breaks.
        while s[i] < n:
            x = c[0] * pow(s[i], e, n) % n # multiplies plaintext_0 by s1
            if oracle(x, privkey, Bits * 2):
                break
            s[i] += 1
        print "Found si?", oracle(x, privkey, Bits * 2), "i=", i, "s=", s[i],
    elif i > 1 and len(M[i-1]) >= 2:
        #print "Step 2.b"
        s.append(s[i-1] + 1) # set s[i]
        while s[i] < n:
            x = c[0] * pow(s[i], e, n) % n # multiplies plaintext_0 by s1
            if oracle(x, privkey, Bits * 2):
                break
            s[i] += 1
        print "Found si?", oracle(x, privkey, Bits * 2), "i=", i, "s=", s[i],
            
    elif len(M[i-1]) == 1:
        #print "Step 2.c"

        #### FIXME this part may be broken, but I wouldn't know
        #### because it rarely executes.

        a = M[i-1][0][0]
        b = M[i-1][0][1]
    
        r2 = 2 * (b*s1 - 2*B) / n # starts here & grows to...
        while r2 < n:
            s2 = (2*B + r2*n)/b # starts here & grows to...
            while s2 < (3*B + r2*n) / a:
                x = c0 * pow(s2, e, n) % n # multiplies plaintext_0 by s2
                if oracle(x, privkey, Bits * 2):
                    break
                s2 += 1
            r2 += 1
        print "Found s2?", oracle(x, privkey, Bits * 2), s2
    
    #### Step 3
    
    #print "Step 3"
    m_set = []
    for [a,b] in M[i-1]:
        rlow = (a * s[i] - 3*B + 1) / n
        rhigh = (b * s[i] - 2*B) / n
        for r in range(rlow, rhigh+1):
            mlow = max(a, ceildiv(2*B + r*n, s[i]))
            mhigh =  min(b, (3*B - 1 + r*n) / s[i])
            if [mlow, mhigh] not in m_set:
                m_set.append([mlow, mhigh])
    M.append(m_set)
    
    #### Step 4
    
    #print "Step 4"
    if len(M[i]) == 1 and M[i][0][0] == M[i][0][1]:
        a = M[i][0][0]
        m = a * rsa.invmod(s[0], n) % n
        print "hooray", m
        print "i2s=", rsa.i2s(m)
        print "s", s
        break
    else:
        if len(M[i]) > 1:
            print "Iterate because len", len(M[i]), ';',
        else:
            print "Iterate because range", M[i][0][0] - M[i][0][1], ';',
        now = time()
        mins = (now-start) / 60
        print round(mins,2), "min. Rt=", round(i / mins, 3)
        i += 1

#### tests ####
short_message2 = "testing"
m2 = pkcs_1(short_message2, Bits*2)
c2 = rsa.encrypt_string(m2, pubkey)
assert oracle(c2, privkey, Bits*2)
warn("Passed assertions:", __file__)
