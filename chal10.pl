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
use Cryptopals qw(aes_cbc);

my $ciphertext;
while(<>){
    chomp;
    die if (length($_)) % 4 != 0; # else need slurp
    $ciphertext .= decode_base64($_); 
}

my $key = "YELLOW SUBMARINE";
my $iv = "\x00" x 16;
print aes_cbc($key, $ciphertext, $iv, "dec");

my @plaintextlines = split(/\n/, aes_cbc($key, $ciphertext, $iv, "dec"));
die unless $plaintextlines[1] =~ /on the mike/;
warn "Passed assertions ($0).\n";
