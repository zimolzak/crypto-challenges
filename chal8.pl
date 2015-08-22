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
use Cryptopals qw(hamming argmax argmin);
use Histogram;
use Rkxor qw(hex2blocks);

my @normdistances;
my @repeat_blocks_per_row;
while(<>){
    chomp;
    my @b = hex2blocks($_, 16);
    my $avg_dist = ( hamming($b[0],$b[1]) +
		     hamming($b[2],$b[3]) +
		     hamming($b[4],$b[5]) ) / 3;
    push @normdistances, $avg_dist / 16;
    my $repeats_this_row = 0;
    for my $i (0..$#b){
	for my $j (0..$#b){
	    next if $i >= $j; # left upper triangle matrix
	    $repeats_this_row++ if $b[$i] eq $b[$j];
	}
    }
    push @repeat_blocks_per_row, $repeats_this_row;
}

my $ax = join(',', argmax(@normdistances)); #um might not want to join.
my $an = join(',', argmin(@normdistances));

print "Line ", $ax+1, " dist $normdistances[$ax], line ",
    $an+1, " dist $normdistances[$an]\n";

print join(" ", @repeat_blocks_per_row), "\n";
