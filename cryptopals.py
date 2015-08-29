#     cryptopals.py - Assorted coversion and calculation functions for
#     Matasano crypto challenges (cryptopals.com).
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

import math

#padding

def pad_multiple(text,blocksize):
    """Return a text, padded out to a multiple of blocksize."""
    n_chars = int(math.ceil(float(len(text)) / blocksize) * blocksize
                  - len(text))
    return text + "\x04" * n_chars

#cbc_enc



#valid padding
