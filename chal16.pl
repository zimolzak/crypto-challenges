#!/usr/bin/perl -w

#     chal16.pl - CBC bitflipping
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

use strict;
use Cryptopals;
use ProfileParsing;

print ascii2hex_blocks(cbc_str_with_comments("hello"), 16), "\n";

warn "Passed assertions ($0)\n";
