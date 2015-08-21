#!/usr/bin/perl 

# Take string of hex chars and output string of base64 chars.

use strict;

use Cryptopals;

print "TEST " . h2b("4d616e") . "\n";
print "Challenge 1 b64: ";
print h2b("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") . "\n";
