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

my $better_try = cbc_str_with_comments("aadminatruea");
#                                         0.....6....11

print ascii2hex_blocks($nice_try, 16), "\n";
print ascii2hex_blocks(flip_bit($nice_try, 10), 16), "\n";

print cbc_cheat($nice_try), "\n";
print cbc_cheat(flip_bit($nice_try, 20)), "\n";

print "x\n";

print join(':', magic_nums_cbc(\&cbc_str_with_comments, $blocksize)), "\n";

warn "Passed assertions ($0)\n";
