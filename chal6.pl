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


# $b = "";
# while(<>){
#     chomp;
#     $b .= $_
# }
# $cipher_hex = b2h($b);
# break_rk_xor($cipher_hex);


$cipher_hex="0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

my $max_key_len = 5; # go up to 40 for full scale. ch5 has 74 by so max 37. I used 20.

break_rk_xor($cipher_hex, $max_key_len);
