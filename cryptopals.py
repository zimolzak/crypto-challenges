#     cryptopals.py - Assorted coversion and calculation functions for
#     Matasano crypto challenges (cryptopals.com).
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from __future__ import print_function
import math
import sys
from Crypto.Cipher import AES

def warn(*objs):
    """Easy and print-as-function way to output to STDERR."""
    print(*objs, file=sys.stderr)

def pad_multiple(text,k):
    """Return a text, padded out to a multiple of blocksize. Now uses
    actual PKCS #7 padding (see RFC 2315 section 10.3, note 2). k is
    the block size.
    """
    l = len(text)
    n_chars = k - (l % k) # Will always add >= 1 char, which is what we want.
    which_char = ["\x00"]
    for charnum in (range(1,k+1)):
        which_char.append(chr(charnum))
    return text + (which_char[n_chars] * n_chars)

class BadPadding(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return "Bad padding: " + repr(self.value)

def strip_padding(string):
    n_chars = ord(string[-1])
    supposed_padding = string[-n_chars:]
    for char in supposed_padding:
        if char != string[-1]:
            raise BadPadding(string)
    return string[:-n_chars]

def xor_str(a,b):
    """Designed for two strings."""
    assert(len(a)==len(b))
    answer = ""
    for i in range(len(a)):
        answer = answer + chr((ord(a[i]) ^ ord(b[i])))
    return answer

def xor_uneq(a,b):
    """Designed for two strings of possibly unequal length."""
    answer = ""
    if len(a) <= len(b):
        for i in range(len(a)):
            answer = answer + chr((ord(a[i]) ^ ord(b[i])))
    else:
        for i in range(len(b)):
            answer = answer + chr((ord(a[i]) ^ ord(b[i])))
    return answer

def int2str(x, nbytes, endian):
    assert(endian=="little" or endian=="big")
    # little means least significant BYTE first.
    string = ""
    if x > 0:
        assert (math.log(x)/math.log(256)) < nbytes
    for bytenum in range(nbytes):
        if endian=="little":
            string = string + chr( (x >> (8 * bytenum)) % 256)
        elif endian=="big":
            string = chr( (x >> (8 * bytenum)) % 256) + string
    return string

def str2int(s):
    # This function assumes big endian.
    assert 0 < len(s) <= 4
    total = 0
    L = list(s)
    L.reverse()
    for i in range(len(L)):
        total += ord(L[i]) << (i*8)
    return total

def ctr(text, key, nonce, endian):
    cipher = AES.new(key, AES.MODE_ECB)
    output = ""
    # make keystream
    keystream = ""
    bs = len(key)
    n_blocks = int(math.ceil(float(len(text)) / bs))
    for i in range(n_blocks):
        counter = int2str(i, bs - len(nonce), endian) # 8 byte counter
        keystream = keystream + cipher.encrypt(nonce + counter)
    # do the encrypt or decrypt
    for i in range(len(text)):
        # need this loop otherwise maybe differing lengths
        output = output + xor_str(keystream[i], text[i])
    return output

def text2blocks(text, bytes):
    blocks = []
    m = int(math.ceil(len(text) / float(bytes))) # number of blocks
    for i in range(m):
        blocks = blocks + [text[bytes*i : bytes*(i+1)]]
    return blocks

def transpose(text, n):
    m = int(math.ceil(len(text) / float(n)))
    B = [""] * n
    A = text2blocks(text, n)
    for i in range(m):
        for j in range(n):
            try:
                B[j] = B[j] + A[i][j]
            except IndexError:
                assert i == m-1 # only on last row of A
    return B

#### Challenge 28 (SHA-1)

def sha1(message):
    assert type(message) == type(str())
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0
    ml = 8 * len(message) # ML is in bits

    #### Pre-process
    n_bytes_to_add = (448 - (ml % 512)) / 8
    padding_string = ""
    for i in range(n_bytes_to_add):
        if i > 0:
            padding_string += '\x00'
        else:
            padding_string += '\x80'
    for i in range(8):
        byte_val = ml >> (64 - 8 * (i + 1)) & 0xff
        # Big endian means R shift by 56, 48, ... , 8, 0.
        padding_string += chr(byte_val)
    message += padding_string
    assert len(message) % (512/8) == 0

    #### Process
    nchunks = int(math.ceil(len(message)/64.0)) # 64 by = 512 bi
    chunks = [message[i*64 : (i+1)*64] for i in range(nchunks)]
    for ch in chunks:
        nwords = int(math.ceil(len(ch)/4.0)) # 4 by = 32 bi
        words = [ch[i*4 : (i+1)*4] for i in range(nwords)]
        w = map(str2int, words)
        for i in range(16, 80):
            w.append(leftrotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16] , 1))
    return w

def leftrotate(x, n):
    assert x <= 0xffffffff
    assert x >= 0
    assert n >= 0
    y = x
    for i in range(n):
        hibit = y & 0x80000000
        y = ((y << 1) + (hibit >> 31)) & 0xffffffff
    return y
    
#### tests ####

assert str2int('~~~~') == 2122219134

assert leftrotate(64,2) == 64 << 2
assert leftrotate(128,1) == 128 << 1
assert leftrotate(242,0) == 242
assert leftrotate(0x80000007,1) == 0x0000000f
assert leftrotate(0xff, 1) == 0x000001fe
assert leftrotate(0xf000000f, 2) == 0xc000003f
assert leftrotate(242, 32) == 242

assert transpose('abcdefghijk', 4) == ['aei', 'bfj', 'cgk', 'dh']

assert text2blocks('abcdefg', 2) == ['ab','cd','ef','g']

assert xor_str('c', 'b') == "\x01"
assert xor_str('c', 'c') == "\x00"
assert xor_str('cb', 'cc') == "\x00\x01"

for test_str in ["hello\x04", "hello\x02\x02"]:
    try:
        x = (strip_padding(test_str))
        assert test_str == "hello\x02\x02"
        assert x == "hello"
    except BadPadding as err:
        assert test_str == "hello\x04"

assert(pad_multiple("YELLOW SUBMARIN",8) == "YELLOW SUBMARIN\x01")
assert(pad_multiple("YELLOW SUBMARINE",8) == "YELLOW SUBMARINE" + "\x08" * 8)

assert(int2str(65534 * 256 + 1,8,"big") == '\x00\x00\x00\x00\x00\xff\xfe\x01')

warn("Passed assertions (" + __file__ + ")")
