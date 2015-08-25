#!/usr/bin/perl 

#     chal1.pl - Take string of hex chars and output string of base64 chars.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

use strict;

use Cryptopals;

print "TEST " . h2b("4d616e") . "\n";
print "Challenge 1 b64: ";
print h2b("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") . "\n";
die unless h2b("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") eq "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
warn "Passed assertion $0.\n";
