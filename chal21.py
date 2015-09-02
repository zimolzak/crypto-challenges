#!/usr/bin/env python

#     chal21.py - Implement MT19937
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn

w = 32          # bit word
n = 624         # degree of recurrence
m = 397         # "middle word"
r = 31          # bits in lower bit mask / sep point of 1 wd
a = 0x9908B0DF  # "coefficients of the rational normal form twist matrix"
u = 11          # mt tem bit shift
d = 0xffffffff  # mt tem bitmask
s = 7           # gfsr temper bit shift
b = 0x9D2C5680  # gfsr temper bitmask
t = 15          # gfsr temper bit shift
c = 0xEFC60000  # gfsr temper bitmask
l = 18          # mt tem bit shift
f = 1812433253

def low_word(x):
    return int((2**w - 1) & x) 

mt = [0] * n
index = n+1 # value that indicates not seeded
lower_mask = (1 << r) - 1                      # usually 0x7fffffff
upper_mask = low_word(lower_mask ^ 0xffffffff) # usually 0x80000000

def seed_mt(seed):
    global mt, index
    index = n
    mt[0] = seed
    for i in range(1, n):
        mt[i] = low_word(f * (mt[i-1] ^ (mt[i-1] >> (w-2))) + i)

class NotSeeded(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return "Generator was never seeded: " + repr(self.value)
        
def extract_number():
    global mt, index
    if index >= n:
        if index > n:
            raise NotSeeded([index, n])
        twist()
    y = mt[index]
    y = y ^ ((y >> u) & d)
    y = y ^ ((y << s) & b)
    y = y ^ ((y << t) & c)
    y = y ^ (y >> 1)
    index += 1
    return low_word(y)

def twist():
    global mt, index
    for i in range(n):
        x = (mt[i] & upper_mask) + (mt[(i + 1) % n] & lower_mask)
        xa = x >> 1
        if (x % 2) != 0:
            xa = xa ^ a
        mt[i] = mt[(i+m) % n] ^ xa
    index = 0

seed_mt(12436)
print extract_number()
print extract_number()
print extract_number()
print extract_number()
print extract_number()
print extract_number()
print extract_number()
print extract_number()

#### tests, if any ####
warn("No errors:", __file__)
