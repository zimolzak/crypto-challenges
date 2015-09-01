#     rkxor.py - Functions to assist analysis of a Repeating Key XOR
#     cipher, akin to a Vigenere cipher.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

from math import ceil
from cryptopals import warn, text2blocks, xor_str
import copy

def break_cipher_given_keysize(keysize_list, ciphertext, func):
    """Works on a generic (abstract) cipher that uses a multi-character
    key. 3rd argument is a pointer to a single char decrypt function
    that does the following: decryptor("J", "0105ffdcba01") -->
    "Hello." Where "J" is a single letter key that gets repeated.
    """

    # 5. Break the ciphertext into blocks of KEYSIZE length.

    print "Trying keys of size " + str(keysize_list)
    for ks in keysize_list: # ks is in bytes
	blocks = text2blocks(ciphertext, ks)
	print "Key size " + str(ks) + " implies " + str(len(blocks)) + " blocks."

    # 6. Now transpose the blocks:

        transposed = []
        for i in range(ks): # white byte to take fr ea block
            for j in range(len(blocks)):
                if j==0 :             # add a new element
		    transposed = transposed + [blocks[j][i]]
                else:
                    if len(blocks[j]) >= i+1:
                        transposed[i] = transposed[i] + blocks[j][i]

    # 7. Solve each block as if it was single-character cipher.

        key_ch_num = 0
        for t in transposed:
	    print "ch " + str(key_ch_num) + " = "
            decrypts = find_generic_decrypts(t, func)
            print decrypts
            print_sig(decrypts);
            key_ch_num = key_ch_num+1

def print_sig(h):
    for k, v in h.iteritems():
        print k,
        print proportion(letters,v),
        print proportion(spaces,v),
        print proportion(misc,v),
        print proportion(unprintable,v)

def xor_char_str(c,s):
    cc = c * len(s)
    return xor_str(cc, s)

def find_generic_decrypts(ciphertext, decrypt_func):
    """Tries to break a *generic* cipher that uses a single-character
    key (not given). This function receives the ciphertext in hex
    and a pointer to a single char decrypt function that does
    something like the following: decryptor("K", "0105ffdcba") -->
    "Hello", where "J" is a single letter key that gets repeated.
    The find_generic_decrypts function makes certain assumptions
    about how the decryptor function operates.
    """
    results = dict()
    metrics = [0.0] * 256
    for charval in range(len(metrics)):
	plaintext = decrypt_func(chr(charval), ciphertext)
        metrics[charval] = metric(plaintext);
    for arg in argmax(metrics):
        if metrics[arg] > 0:
            results[chr(arg)] = decrypt_func(chr(arg), ciphertext)
    return results

def metric(text):
    """Higher metric means more likely to be English. Remember,
    proportion() does its work in a case-insensitive manner already.
    """
    is_strict_decreasing = (
	(proportion(letters,text) > proportion(spaces,text)) &
	(proportion(spaces,text) >= proportion(misc,text)) &
	(proportion(misc,text) >= proportion(unprintable,text))
	)
    return proportion(letters, text) * is_strict_decreasing

def argmax(x):
    """Operate on a list, return a list of all indices of the max
    value.
    """
    sorted = copy.copy(x)
    sorted.sort(reverse=True)
    arg_list = []
    for i in range(len(x)):
        if x[i] == sorted[0]:
            arg_list += [i]
    return arg_list

letters = "abcdefghijklmnopqrstuvwxyz"
spaces = "\r\n "
unprintable = ""
for i in range(0,10) + [11,12] + range(14,32) + [127]:
    unprintable = unprintable + chr(i)
misc=""
for i in range(33,65) + range(91,97) + range(123,127):
    misc = misc + chr(i)

def proportion(charset, string):
    charset = charset.upper()
    string = string.upper()
    found = 0
    for s in string:
        for c in charset:
            if s==c:
                found = found + 1
    return float(found) / (len(string))

# tests
assert argmax([3, 4, 5, 3, 8, 5, 7, 4, 34, 5, 3, 4, 6]) == [8]
assert proportion(letters, "Hello world") == 10.0 / 11.0
assert metric("Hello world")  == 10.0 / 11.0
assert metric("Hello,,,,,,,,,,,,,,world")  == 0

warn("Passed assertions (" + __file__ + ")")

