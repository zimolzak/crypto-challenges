#!/usr/bin/perl -w

#     chal16.pl - CBC bitflipping
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

use strict;
use Cryptopals;
use ProfileParsing;

my $hello = cbc_str_with_comments("hello");
my $nice_try = cbc_str_with_comments("x;admin=true");

die unless cbc_cheat($hello) =~ /hello/;
die if cipher_is_admin($hello);
die if cipher_is_admin($nice_try); 

warn "Passed assertions ($0)\n";
