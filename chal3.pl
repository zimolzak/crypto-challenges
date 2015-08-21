#!/usr/bin/perl -w
use strict;
use Cryptopals;

# find single char, XOR it against ciphertext, score english plaintext.

print "Challenge 3\n";

my $cipher_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

my %decrypts = %{find_decrypts($cipher_hex)};

printhash(%decrypts);
