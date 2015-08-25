#!/usr/bin/perl -w

#     chal3.pl - Find single char, XOR it against ciphertext, score
#     English plaintext.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

use strict;
use Cryptopals;

print "Challenge 3\n";

my $cipher_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

my %decrypts = %{find_scxor_decrypts($cipher_hex)};

print "Key -> plaintext\n";
printhash(%decrypts);

my $plaintext = $decrypts{"X"};
die unless $plaintext =~ /like a pound/;
warn "Passed assertion $0\n";
