#!/usr/bin/env python

#     chal43.py - DSA key recovery from nonce
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
from rsa import invmod
from hashlib import sha1
import time
from dsa import p, q, g, find_private_key, sign
import random

x = random.randint(1, q) # private key
y = pow(g, x, p)
public = [p, q, g, y] # Turns out we don't even need y.

test_string = """For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch
"""

H_string = sha1(test_string).hexdigest()
print "Hash of test msg =", H_string
H = int("0x" + H_string, 16)

r, s = sign(test_string, g, p, q, x)
print "With random nonce k,"
print "r =", r
print "s =", s
print

#### Breaking, given a signature [r,s], and given that k <= 2**16.
#### Also of course given parameters g, p, q, and hash H of message.

print "Searching for k (nonce, subkey) and thus x (private key)...."
matasano_r = 548099063082341131477253921760299949438196259240
matasano_s = 857042759984254168557880549501802188789837994940
k_found = 0
x_found = 0
start = time.time()
for k in range (1, 2 ** 16):
    r = pow(g, k, p) % q
    x = find_private_key(matasano_r, matasano_s, k, H, q)
    s = ((H + x * r) * invmod(k, q)) % q
    if s == matasano_s and r == matasano_r:
        print "k =", k
        print "x =", x
        k_found = k
        x_found = x
        # Deciding not to break out of the for loop, in rare event
        # there would be two valid values of k.
end = time.time()
dur = end - start
rate = k / dur
print "Tried", k, "nonces in", int(dur), "s, for", int(rate), "per s."
# 5800 per sec on MacBook Pro 8,1 (early 2011, OS X, 2.7 GHz Intel Core i7)

S = hex(x_found).replace("L", "").replace("0x", "")
print S
final = sha1(S).hexdigest()
print final

#### tests ####
# Both of these were copied right off the Web site,
# http://cryptopals.com/sets/6/challenges/43/
assert H_string == "d2d0714f014a9784047eaeccf956520045c45265"
assert final == "0954edd5e0afe5542a4adf012611a91912a3ec16"
warn("Passed assertions:", __file__)
