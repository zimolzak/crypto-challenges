#!/usr/bin/env python

#     chal44.py - DSA key recovery from repeated nonce
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
from rsa import invmod
from dsa import p, q, g, find_private_key
from hashlib import sha1

y_str = """2d026f4bf30195ede3a088da85e398ef869611d0f68f07
13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8
5519b1c23cc3ecdc6062650462e3063bd179c2a6581519
f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430
f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3
2971c3de5084cce04a2e147821"""

y = int(y_str.replace("\n", ""), 16)

all_past = []
# Goal: find two messages that use the same k. r = g**k % p. In other
# words, repeated r means repeated k. Therefore keep running list of
# all msg, s, r, m values we have seen, and break once we see a
# repeated r. all_past will be a list of dicts.

def first_row_where(ki, vi, list_of_dict):
    for row in list_of_dict:
        for k, v in row.iteritems():
            if k == ki and v == vi:
                return row
    return False

#### parse the file
row2 = {}
for line in open('44.txt', 'r').read().splitlines():
    key, val = line.split(': ')
    if key == 'msg':
        row2 = {}
    if key == 's' or key == 'r':
        exec('row2["' + key + '"] = ' + val) # int means no quote
    else:
        exec('row2["' + key + '"] = "' + val + '"') # str means quote
    if key != 'm':
        continue
    #### Find repeated r
    row1 = first_row_where('r', row2['r'], all_past)
    if not row1:
        all_past.append(row2)
        continue
    #### get cracking
    m1 = int(row1['m'], 16)
    m2 = int(row2['m'], 16)
    k = ((m1 - m2) *
         invmod((row1['s'] - row2['s']), q) %
         q)
    print "k =", k
    x = find_private_key(row1['r'], row1['s'], k, m1, q)
    print "x =", x
    hex_x = hex(x).replace('0x','').replace('L','')
    s1x = sha1(hex_x).hexdigest()
    print "sha1(x) =", s1x
    break

#### tests ####
h = [{'a':10, 'b':9, 'c':4}, {'a':777, 'b':99, 'c':42}, {'a':11, 'b':10, 'c':4}]
assert first_row_where('c', 42, h) == {'a': 777, 'c': 42, 'b': 99}
assert s1x == "ca8f6f7c66fa362d40760d135b763eb8527d3d52"
warn("Passed assertions:", __file__)
