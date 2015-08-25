#!/usr/bin/perl -w

#     chal14.pl - Break ECB with known plaintext in middle.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

use strict;
use MIME::Base64 qw(decode_base64);

use Cryptopals qw(aes_ecb pad_multiple encryption_oracle
    random_bytes ascii2hex_blocks);

use Crypt::OpenSSL::AES;
use BreakECB;

# setup key

my $key;
open(PW, "< unknown_key.txt") || die("Can't open password file: $!");
while(<PW>){
    chomp;
    $key = $_;
}
close PW || die("Can't close password file: $!");

# setup unknown text

my $unknown_b64 = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK';
my $unknown_string = decode_base64($unknown_b64);

# setup random prefix

open(RB, "< rand_bytes.txt") || die("Can't open random byte file: $!");
local $/; #slurp
my $random_prefix = <RB>;
close RB || die("Can't close random byte file: $!");
local $/ = "\n";

# setup func

sub insert_encrypt {
    my ($attacker_controlled) = @_;
    my $enc_me = $random_prefix . $attacker_controlled . $unknown_string;
    $enc_me = pad_multiple($enc_me, length($key));
    return aes_ecb($key, $enc_me, "enc");
}

# Prelim analysis

my $blocksize = find_ecb_blocksize(\&insert_encrypt);
print "Algorithm block size is :\t** ", $blocksize, " **\n";
my $pre = "Hello!" x 200;
print "Algorithm mode is:\t\t** ",
    encryption_oracle(insert_encrypt($pre)), " **\n";
die unless encryption_oracle(insert_encrypt($pre)) eq "ECB";

# real analysis

print ascii2hex_blocks(insert_encrypt("A" x 48), 16), "\n";

warn "Passed assertions ($0)\n";
