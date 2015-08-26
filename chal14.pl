#!/usr/bin/perl -w

#     chal14.pl - Break ECB with known plaintext in middle.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

use strict;
use MIME::Base64 qw(decode_base64);

use Cryptopals qw(aes_ecb pad_multiple encryption_oracle
    random_bytes ascii2hex_blocks split_bytes);

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

#for my $n (16..48){
#    print "$n: ", ascii2hex_blocks(insert_encrypt("A" x $n), $blocksize), "\n";
#}

print "\n----\n";
my ($n, $i) = magic_nums_of_infix(\&insert_encrypt, $blocksize);
print "w00t $n $i \n";

print find_str_infix(\&insert_encrypt, $blocksize);

sub ident {
    my ($s) = @_;
    return "junk" . $s . "secret";
}

my $pre_fp = infix2prepend(\&ident, 2);

print &$pre_fp("hellohellohello"), "\n";


# 42 is magic num, or 26. Add 26 bytes of junk and throw out first 3
# blocks, and you have made a prepender-type function.

# find the first iteration where there are 2 identical blocks in
# tandem. That means they are two 'AAAAAAAAAAAAAAAA' blocks. And the
# next blocks after that are part of the target. I elected to copy
# paste in the hex rather than code this up.

my $target_hex = 'ef9fed348fdd89f043f809a544d2a707364506842f21a5f8b19108ef689512c8eacd8c0cdddb6c289c74a6dc7886b9f10df86d02b3d4eff4361b56586781b6c08daad09af5f863040a0b8acedb40e1d0e30005843dbd7553ef9266dadff4c4be386060e6c655af9979743b65cf4b1fb9fb1ac2096e7e23f5b68d241792ca5955af5d52e71ddaee8808c06a985bbe83ec';



warn "Passed assertions ($0)\n";
