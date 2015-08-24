#!/usr/bin/perl -w

#     chal10.pl - Implement CBC mode
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

# usage: ./chal10.pl 10.txt

use strict;
use MIME::Base64 qw(decode_base64);
use Crypt::OpenSSL::AES;
use Cryptopals qw(aes_cbc encrypt_randomly ascii2hex);

my $ciphertext;
while(<>){
    chomp;
    die if (length($_)) % 4 != 0; # else need slurp
    $ciphertext .= decode_base64($_); 
}

my $key = "YELLOW SUBMARINE";
my $block = substr($ciphertext, 0, 16);
my $iv = "\x00" x 16;
print aes_cbc($key, $ciphertext, $iv, "dec");

my @plaintextlines = split(/\n/, aes_cbc($key, $ciphertext, $iv, "dec"));
die unless $plaintextlines[1] =~ /on the mike/;

my $text = "Got me a movie, I want you to k\n";
my $ciph = aes_cbc($key, $text, $iv, "enc");
my $decrypt = aes_cbc($key, $ciph, $iv, "dec");
die unless $text eq $decrypt;

print "Passed assertions (challenge 10)\n";

print ascii2hex(encrypt_randomly($text)), "\n";
print ascii2hex(encrypt_randomly($text)), "\n";
print ascii2hex(encrypt_randomly($text)), "\n";
print ascii2hex(encrypt_randomly($text)), "\n";


