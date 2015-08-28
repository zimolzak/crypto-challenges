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

my @targ_bytes = (0,6,11);
my $found = 0;
for my $b0(0..8){
    for my $b1(0..8){
	for my $b2(0..8){
	    my $i0 = (($throw-1) * $blocksize + $targ_bytes[0])*8 + $b0;
	    my $i1 = (($throw-1) * $blocksize + $targ_bytes[1])*8 + $b1;
	    my $i2 = (($throw-1) * $blocksize + $targ_bytes[2])*8 + $b2;
	    my $ciph = flip_bit(flip_bit(flip_bit($better_try
						  , $i0), $i1), $i2);
	    print cbc_cheat($ciph), "\n"; #deleteme
	    if (cipher_is_admin($ciph)) {
		print "Broke CBC! with:\n";
		print $ciph, "\n";
		print ascii2hex($ciph);
		print "Bits to flip: $i0 $i1 $i2\n";
		$found = 1;
		last;
		# This fails because I am flipping only one bit per
		# byte, not all bits per byte. Search space of 2^3
		# instead of 2^24. But wait - brute force is silly
		# because the plaintext I have to bitflip is already
		# known! So just transmute a-->; and a-->=.
	    }
	}
    }
}

die unless $found;

warn "Passed assertions ($0)\n";
