#!/usr/bin/perl 

#     chal9.pl - Implement PKCS#7 padding
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

use strict;
use Cryptopals qw(pad_text);

print pad_text("YELLOW SUBMARINE", 20), "\n";

die unless length(pad_text("YELLOW SUBMARINE", 20)) == 20;
die unless pad_text("YELLOW SUBMARINE", 20)
    eq "YELLOW SUBMARINE\x04\x04\x04\x04";
warn "Passed assertions $0.\n";
