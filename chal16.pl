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


print ascii2hex_blocks($nice_try, 16), "\n";
print ascii2hex_blocks(flip_bit($nice_try, 10), 16), "\n";

print cbc_cheat($nice_try), "\n";
print cbc_cheat(flip_bit($nice_try, 20)), "\n";

print "x\n";

my ($junk, $throw) = magic_nums_cbc(\&cbc_str_with_comments, $blocksize);


my $better_try = cbc_str_with_comments(("Q" x $junk) . "aadminatruea");
#                                                       0.....6....11
print cbc_cheat($better_try), "\n";

print cbc_cheat(flip_bit($better_try,256)), "\n";

print "$junk, $throw\n----\n\n";



# comment1=cooking%20MCs;userdata=QQQQQQQQQQQQQQQQaadminatruea;comment2=%20like%20a%20pound%20of%20bacon;

my @targ_bytes = (0,6,11);
for my $b0(0..8){
    for my $b1(0..8){
	for my $b2(0..8){
	    my $i0 = (($throw-1) * $blocksize + $targ_bytes[0])*8 + $b0;
	    my $i1 = (($throw-1) * $blocksize + $targ_bytes[1])*8 + $b1;
	    my $i2 = (($throw-1) * $blocksize + $targ_bytes[2])*8 + $b2;
	    print "$i0 $i1 $i2 ";
	    # my $s0 = flip_bit($better_try, $i0);
	    # my $s1 = flip_bit($s0, $i1);
	    # my $s2 = flip_bit($s1, $i2);
	    print cbc_cheat(flip_bit(flip_bit(flip_bit($better_try, $i0), $i1), $i2)), "\n";
	    # print "    ", cbc_cheat($s0), "\n";
	    # print  "    ", cbc_cheat($s1), "\n";
	    # print  "    ", cbc_cheat($s2), "\n";
	}
    }
}

warn "Passed assertions ($0)\n";
