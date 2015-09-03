#!/usr/bin/env python

#     chal23.py - Clone MT19937
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
from myrand import MTRNG, c, b, u, s, t, l, n

def untemper_partial(input, k, mask):
    output = input
    bits = k
    while bits < 32:
        if mask == "right":
            output = input ^ (output >> k)
        else:
            output = input ^ ((output << k) & mask)
        bits += k
    return output

def untemper(y4):
    y3 = untemper_partial(y4, l, "right")
    y2 = untemper_partial(y3, t, c)
    y1 = untemper_partial(y2, s, b)
    return untemper_partial(y1, u, "right")

answer = untemper(0xe016575d)
print "Untemper result is:", hex(answer)

rng = MTRNG(67812)
state = [0] * n
for i in range(n):
    state[i] = untemper(rng.extract_number())

clone = MTRNG(state)

print "Cloning results are:"

for i in range(10):
    x = clone.extract_number()
    y = rng.extract_number()
    print x, y
    assert x == y

#### tests, if any ####
assert answer == 0xdeadbeef
warn("Passed assertions:", __file__)
