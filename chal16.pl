#!/usr/bin/perl -w

#     chal16.pl - CBC bitflipping
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

use strict;
use Cryptopals;
use ProfileParsing;
use CBCBitflip;
use BreakECB qw(magic_nums_of_infix find_ecb_blocksize);

my $hello = cbc_str_with_comments("hello");
my $nice_try = cbc_str_with_comments(";admin=true");

die unless cbc_cheat($hello) =~ /hello/;
die if cipher_is_admin($hello);
die if cipher_is_admin($nice_try);

# prelim

my $blocksize = find_ecb_blocksize(\&cbc_str_with_comments);
print "Algorithm block size is :\t** ", $blocksize, " **\n";
my $pre = "Hello!" x 200;
print "Algorithm mode is:\t\t** ",
    encryption_oracle(cbc_str_with_comments($pre)), " **\n";

## break crypto

my ($junk, $throw) = magic_nums_cbc(\&cbc_str_with_comments, $blocksize);

my $better_try = cbc_str_with_comments(("Q" x $junk) . "aadminatruea");
#                                                       0.....6....11

my @byte = (0,6,11);
my @ini_char = qw(a a a);
my @fin_char = qw(; = ;);

for my $i (0..$#byte) {
    $better_try = flip_mask($better_try, ($throw-1) * $blocksize + $byte[$i],
			    $ini_char[$i] ^ $fin_char[$i]);
}

if (cipher_is_admin($better_try)){
    print "\nBroke CBC! with:\n";
    print "Plaintext: ", cbc_cheat($better_try), "\n";
    print "Plaintext: ", ascii2hex_blocks(cbc_cheat($better_try), $blocksize)
	, "\n";
    print "Ciphertext: ", ascii2hex_blocks($better_try, $blocksize), "\n";
}

die unless cipher_is_admin($better_try);

warn "Passed assertions ($0)\n";
