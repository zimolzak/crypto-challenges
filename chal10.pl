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
use Cryptopals qw(aes_ecb_decrypt);

my $ciphertext;
while(<>){
    chomp;
    # no slurp if all lines have multiple of four base64 chars
    die if (length($_)) % 4 != 0; 
    $ciphertext .= decode_base64($_); 
}

my $key = "YELLOW SUBMARINE";
print aes_ecb_decrypt($key, $ciphertext); # expect to fail because ecb.

# my @plaintextlines = split(/\n/, aes_ecb_decrypt($key, $ciphertext));
# die unless $plaintextlines[1] =~ /BLAHBLAHBLAH/;
# print "Passed assertion\n";
