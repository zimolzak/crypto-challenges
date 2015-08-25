#!/usr/bin/perl -w

#     chal11.pl - ECB/CBC detection oracle
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

use strict;
use Crypt::OpenSSL::AES;
use Cryptopals qw(aes_cbc encrypt_randomly encryption_oracle);

my $key = "YELLOW SUBMARINE";
my $iv = "\x00" x 16;
my $text = "Got me a movie, I want you to k\n";

my $ciph = aes_cbc($key, $text, $iv, "enc"); # enc hasn't been tested til now
my $decrypt = aes_cbc($key, $ciph, $iv, "dec");
die unless $text eq $decrypt;

for (1..100){
    my ($ciphertext, $chosen_mode) = encrypt_randomly($text);
    die unless encryption_oracle($ciphertext) eq $chosen_mode;
}
warn "Passed assertions ($0)\n";
