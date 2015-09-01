#     rkxor.py - Functions to assist analysis of a Repeating Key XOR
#     cipher, akin to a Vigenere cipher.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

from math import ceil

def break_cipher_given_keysize(keysize_list, ciphertext, func):
    """Works on a generic (abstract) cipher that uses a multi-character
    key. 3rd argument is a pointer to a single char decrypt function
    that does the following: decryptor("J", "0105ffdcba01") -->
    "Hello." Where "J" is a single letter key that gets repeated.
    """

    # 5. Break the ciphertext into blocks of KEYSIZE length.

    print "Trying keys of size " + ', '.join(keysize_list)
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
    metrics = [0.0] * 255
    for charval in range(256):
	plaintext = decrypt_func(chr(charval), ciphertext)
        metrics[charval] = metric(plaintext);
    for arg in argmax(metrics):
        if metrics[arg] > 0:
            results[chr(arg)] = decrypt_func(chr(arg), ciphertext)
    return results

def metric():
    return 1

def argmax():
    return 1

def proportion():
    return 1
