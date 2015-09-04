#!/usr/bin/env python

#     myrand.py - Implement MT19937
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

import cryptopals
import time

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

lower_mask = (1 << r) - 1                      # usually 0x7fffffff
upper_mask = low_word(lower_mask ^ 0xffffffff) # usually 0x80000000

class BadSeed(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return "Cannot seed RNG with this value: " + repr(self.value)

class MTRNG():
    def __init__(self, seed):
        if type(seed) == type(1):
            self.mt = [0] * n
            self.index = n
            self.mt[0] = seed
            for i in range(1, n):
                self.mt[i] = low_word(f * (self.mt[i-1]
                                           ^ (self.mt[i-1] >> (w-2))) + i)
        elif type(seed) == type(list()):
            assert len(seed) == n
            self.mt = seed
            self.index = n
        else:
            raise BadSeed(seed)

    def extract_number(self):
        if self.index >= n:
            self.twist()
        y = self.mt[self.index] # retrieve from MT[]
        # begin tempering
        y = y ^ ((y >> u) & d)  # note d = 0xffffffff
        y = y ^ ((y << s) & b)
        y = y ^ ((y << t) & c)
        y = y ^ (y >> l) # lowercase L, not numeral 1
        self.index += 1
        return low_word(y)

    def twist(self):
        for i in range(n):
            x = (self.mt[i] & upper_mask) + (self.mt[(i + 1) % n] & lower_mask)
            xa = x >> 1
            if (x % 2) != 0:
                xa = xa ^ a
            self.mt[i] = self.mt[(i+m) % n] ^ xa # store new into MT[]
        self.index = 0

class NoTimeSeed(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return "Number may be from RNG not seeded with time" + repr(self.value)

def find_time_seed(target_num):
    now = int(time.time())
    for s in range(now - 60 * 35, now + 60 * 2):
        m = MTRNG(s)
        if m.extract_number() == target_num:
            return s
    raise NoTimeSeed(target_num)

#### tests, if any ####
cryptopals.warn("No errors:", __file__)
