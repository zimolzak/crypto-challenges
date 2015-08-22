#!/usr/bin/perl -w

#     chal8.pl - Detect AES in ECB mode (from file of about 200 hex
#     strings, one per line, each about 160 bytes).
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

# usage: ./chal8.pl 8.txt

use strict;
use Crypt::OpenSSL::AES;
use Cryptopals qw(aes_ecb_decrypt hex2ascii);
use Histogram;
use Rkxor qw(break_cipher_given_keysize);

sub aes_key_hex {
    my ($key, $cipher_hex) = @_;
    my $ciphertext = hex2ascii($cipher_hex);
    return aes_ecb_decrypt($key, $ciphertext);
}

while(<>){
    chomp;
    my @keysizelist = (16);
    my $kspointer = \@keysizelist;
    # print aes_ecb_decrypt($key, $ciphertext), "\n";
    # print_sig(($key, aes_ecb_decrypt($key, $ciphertext) . "\n"));
    break_cipher_given_keysize($kspointer, $_, \&aes_key_hex);
}
