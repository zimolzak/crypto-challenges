#!/usr/bin/perl -w

#     chal7.pl - Read base64 AES-ECB cipher, decrypt w/ known key.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

# usage: ./chal7.pl 7.txt

use strict;
use MIME::Base64 qw(decode_base64);
use Crypt::OpenSSL::AES;
use Cryptopals qw(aes_ecb);

my $ciphertext;
while(<>){
    chomp;
    # no slurp if all lines have multiple of four base64 chars
    die if (length($_)) % 4 != 0; 
    $ciphertext .= decode_base64($_); 
}

my $key = "YELLOW SUBMARINE";
print aes_ecb($key, $ciphertext, "dec");

my @plaintextlines = split(/\n/, aes_ecb($key, $ciphertext, "dec"));
die unless $plaintextlines[0] =~ /back and I/;
print "Passed assertion\n";
