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
use Cryptopals qw(aes_ecb_decrypt hex2ascii hamming argmax argmin);
use Histogram;
use Rkxor qw(break_cipher_given_keysize hex2blocks);

sub aes_key_hex {
    my ($key, $cipher_hex) = @_;
    my $ciphertext = hex2ascii($cipher_hex);
    return aes_ecb_decrypt($key, $ciphertext);
}

my @normdistances;
while(<>){
    chomp;
    my @b = hex2blocks($_, 16);
    my $avg_dist = ( hamming($b[0],$b[1]) +
		     hamming($b[2],$b[3]) +
		     hamming($b[4],$b[5]) ) / 3;
    push @normdistances, $avg_dist / 16;
    print "$.: ", $avg_dist / 16, "\n";
}

my $ax = join(',', argmax(@normdistances));
my $an = join(',', argmin(@normdistances));

print "\n\n";

print argmax(@normdistances), " $ax\n";

print "Line ", $ax+1, " dist $normdistances[$ax], line ",
    $an+1, " dist $normdistances[$an]\n";
