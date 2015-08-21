#!/usr/bin/perl -w
# usage ./chal6.pl 6.txt > out.txt

use strict;
use Cryptopals qw(hamming h2b b2h ascii2hex);
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

$b = "";
while(<>){
    chomp;
    $b .= $_
}

$cipher_hex = b2h($b);


break_rk_xor($cipher_hex);
