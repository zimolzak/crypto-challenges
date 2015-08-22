#!/usr/bin/perl -w

#     chal4.pl - Decrypt a bunch of hex strings, assuming single-char
#     XOR, so I can scan thru output and pick out the one real one.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

# usage: ./chal4.pl 4.txt > out.txt

use strict;
use Cryptopals;

while(<>){
    chomp;
    my %best4line = %{find_scxor_decrypts($_)};
    print $_, "\n----\n";
    printhash(%best4line);
    print "\n\n";
}
