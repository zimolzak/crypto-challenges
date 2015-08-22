#!/usr/bin/perl -w

#     chal2.pl - Just test XOR'ing two hex strings.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

use strict;
use Cryptopals

print "Challenge 2 XOR result: ";

print hex_xor_hex("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965") . "\n";

die unless hex_xor_hex("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965") eq "746865206b696420646f6e277420706c6179";

print "Passed assertion.\n";

