#     rkxor.py - Functions to assist analysis of a Repeating Key XOR
#     cipher, akin to a Vigenere cipher.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

from math import ceil
from cryptopals import hamming

def text2blocks(text, bytes):
    blocks = []
    m = int(ceil(len(text) / float(bytes))) # number of blocks
    for i in range(m):
        blocks = blocks + [text[bytes*i : bytes*(i+1)]]
    return blocks

assert text2blocks('abcdefg', 2) == ['ab','cd','ef','g']

def find_keysize(ciphertext, max_key_len):
    """Take a ciphertext presumed to be encrypted with repeating key XOR.
    Parameters are what is max key size to try. Return the most likely
    key sizes in order.
    """
    keysizelist = range(2, max_key_len+1)
    normdistances = dict()
    for keysize in keysizelist:
	b = text2blocks(ciphertext, keysize)
        n_samples = 3
        if len(b) < 7:
            n_samples = int(len(b) / 2.0) - 1
        avg_dist = 0
        for i in range(n_samples):
            avg_dist = avg_dist + hamming(b[i*2], b[i*2+1])
        avg_dist = avg_dist / n_samples
	normdistances[keysize] = avg_dist / keysize
    return sorted(normdistances, key=normdistances.get)

def break_rk_xor(ciphertext, max_key_len):
    keysizelist = range(2, max_key_len+1)
    normdistances = dict()

    # 3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and
    # the second KEYSIZE worth of bytes, and find the edit distance.
    
    for keysize in keysizelist:
	b = text2blocks(ciphertext, keysize)
	avg_dist = ( hamming(b[0],b[1]) +
                     hamming(b[2],b[3]) +
                     hamming(b[4],b[5]) ) / 3
	normdistances[keysize] = avg_dist / keysize

    # 4. The KEYSIZE with the smallest normalized edit distance is
    # probably the right keysize.

    N_top_keysizes = 5
    best_key_sizes = sorted(normdistances, key=normdistances.get)
    keysizes_to_try = best_key_sizes[0 : N_top_keysizes]
    break_cipher_given_keysize(keysizes_to_try, ciphertext, xor_str)



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
