#!/usr/bin/perl -w

#     chal6.pl - Input a base64 ciphertext, apply a function that will
#     guess key length and determine print parts of possible keys from
#     English-looking results. Takes about 40 sec on my MacBook Pro
#     (2.7 GHz Intel Core i7).
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

# usage ./chal6.pl 6.txt > out.txt

use strict;
use Cryptopals qw(hamming h2b b2h ascii2hex key_xor_hex_to_text);
use Histogram qw(print_sig);
use Rkxor;

# use MIME::Base64;

#tests
die unless hamming(ascii2hex("this is a test"),
		   ascii2hex("wokka wokka!!!")) == 37;
my $cipher_hex = "ff00abc12";
my $b = h2b($cipher_hex);
die unless b2h($b) eq $cipher_hex;
$b = "dsfwqeiufhoisfvuhbiufhwqriufhgikfughuir372ty4u87234tr8wegf87wghe";
$cipher_hex = b2h($b);
die unless h2b($cipher_hex) eq $b;


# main

my $max_key_len = 40; # go up to 40 for full scale. ch5 has 74 by so max 37. I used 20 or 5.

$b = "";
while(<>){
    chomp;
    $b .= $_
}
$cipher_hex = b2h($b);
break_rk_xor($cipher_hex, $max_key_len); # runme

my $key = "Terminator X: Bring the noise"; # obtained by inspection of output.
print key_xor_hex_to_text($key, $cipher_hex);
print "\n";

my @plaintextlines = split(/\n/, key_xor_hex_to_text($key, $cipher_hex));

die unless $plaintextlines[0] =~ /back and I/;

warn "Passed assertion $0\n";
