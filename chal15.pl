#!/usr/bin/perl -w

#     chal15.pl - PKCS#7 padding validation
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

use strict;
use Cryptopals qw(strip_valid_padding);
#use Error qw(:try);
#use Exception::Class;
use Try::Tiny;


try {
    print strip_valid_padding("hello\x01\n");
}
catch {
    chomp;
    if (/Bad padding/) {
	print $_, " Boo!\n" ;
    }
    else {
	print "some other error\n";
    }
};

warn "Passed assertions ($0)\n";
