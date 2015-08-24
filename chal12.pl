#!/usr/bin/perl -w

#     chal12.pl - Break ECB
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

use strict;
use MIME::Base64 qw(decode_base64);

use Cryptopals qw(aes_ecb pad_text ceil encryption_oracle aes_cbc
    random_bytes);

use Crypt::OpenSSL::AES;
use BreakECB qw(find_ecb_blocksize);

my $key;
open(PW, "< unknown_key.txt") || die("Can't open password file: $!");
# unknown_key.txt was something I copy/pasted from
# https://www.random.org/strings made up of 16 bytes of only [A-Za-z].
# I didn't look at it (much) before pasting it into the file, which I
# did so it wouldn't be there in the code staring at me.
while(<PW>){
    chomp;
    $key = $_;
}
close PW || die("Can't close password file: $!");

my $unknown_b64 = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK';

my $unknown_string = decode_base64($unknown_b64);


my $ciphertext = aes_ecb($key,
			 pad_text(
			     $unknown_string,
			     ceil(length($unknown_string)/16) * 16),
			 "enc");

die unless $unknown_string ne $ciphertext;

sub prepend_encrypt {
    my ($yourstring) = @_;
    my $enc_me = $yourstring . $unknown_string;
    $enc_me = pad_text($enc_me, ceil(length($enc_me)/16) * 16);
    return aes_ecb($key, $enc_me, "enc");
}

sub prepend_cbc {
    my ($yourstring) = @_;
    my $enc_me = $yourstring . $unknown_string;
    $enc_me = pad_text($enc_me, ceil(length($enc_me)/16) * 16);
    my $iv = random_bytes(16);
    return aes_cbc($key, $enc_me, $iv, "enc");
}

# 1. Discover the block size of the cipher.

print "Algorithm block size is :\t** ",
    find_ecb_blocksize(\&prepend_encrypt), " **\n";

# 2. Detect that the function is using ECB

my $pre = "Hello!" x 200;
print "Algorithm mode is:\t\t** ",
    encryption_oracle(prepend_encrypt($pre)), " **\n";
die unless encryption_oracle(prepend_encrypt($pre)) eq "ECB";
die unless encryption_oracle(prepend_cbc($pre)) eq "CBC";

print "passed assertions (challenge 12).\n";
