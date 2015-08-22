#!/usr/bin/perl -w

#     chal7.pl - Read base64 AES-ECB cipher, decrypt w/ known key.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

use strict;
use MIME::Base64 qw(decode_base64);
use Crypt::OpenSSL::AES;
use Cryptopals qw(ascii2hex);
use Crypt::CBC;
#use Crypt::Mode::ECB;

print Crypt::OpenSSL::AES->VERSION, "\n";

my $ciphertext;
while(<>){
    chomp;
    # no slurp if all lines have multiple of four base64 chars
    die if (length($_)) % 4 != 0; 
    $ciphertext .= decode_base64($_); 
}

my $key = "YELLOW SUBMARINE";

warn "len = ", length($ciphertext), ". Len mod 16 = ",
(length($ciphertext) % 16), ".\n";

# can't use Crypt::OpenSSL::AES directly; wants EXACTLY 16 bytes.
#      my $cipher = new Crypt::OpenSSL::AES($key);

my $cipher = Crypt::CBC->new(
    -key    => $key,
    -cipher => "Crypt::OpenSSL::AES",
#    -header => "none"
    ); # depend on Crypt::DES ??

my $test = $cipher->encrypt("Hiya\n");
print "Secret! ", ascii2hex($test), "\n";
print $cipher->decrypt($test);

my $aes = new Crypt::OpenSSL::AES($key);

for (my $i=0; my $block = substr($ciphertext, 16*$i, 16); $i++) {
    print $aes->decrypt($block);
}

print $cipher->decrypt($ciphertext);
print "\n";
