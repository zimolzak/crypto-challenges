#!/usr/bin/perl -w

#     chal15.pl - PKCS#7 padding validation
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

use strict;
use Cryptopals qw(strip_valid_padding);
use Try::Tiny;

try {
    print strip_valid_padding("ICE ICE BABY\x04\x04\x04\x04"), "\n";
}
catch {
    if (/Bad padding/) {
	chomp;
	die "Error in GOOD string?! ($_)$!";
    }
    else {
	chomp;
	die "unknown error $_ $!";
    }
};

try {
    print strip_valid_padding("ICE ICE BABY\x05\x05\x05\x05"), "\n";
    die "Bad string 1 failed to throw exception$!";
}
catch {
    if (/Bad padding/) {
	print "Caught, as predicted.\n";
    }
    else {
	chomp;
	die "unknown error ($_)$!";
    }
};

try {
    print strip_valid_padding("ICE ICE BABY\x01\x02\x03\x04"), "\n";
    die "Bad string 2 failed to throw exception$!";
}
catch {
    if (/Bad padding/) {
	print "Caught, as predicted.\n";
    }
    else {
	chomp;
	die "unknown error ($_)$!";
    }
};

warn "Passed assertions ($0)\n";
