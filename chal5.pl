#!/usr/bin/perl -w
use strict;
use Cryptopals qw(key_xor_hex_to_text ascii2hex);

my $plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";

#print ascii2hex($plaintext);

print ascii2hex(key_xor_hex_to_text("ICE", ascii2hex($plaintext))), "\n";

my $target = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

die unless ascii2hex(key_xor_hex_to_text("ICE", ascii2hex($plaintext))) eq $target;

#print key_xor_hex_to_text("A", "70");

for my $plaintext ("Hello", "Testing this", "asdfsdfwef", "Bruce lee was a german swiss physicist.") {
    print "$plaintext\t|\t";
    print key_xor_hex_to_text("sucka mcs", ascii2hex($plaintext)), "\t|\t";
    print ascii2hex(key_xor_hex_to_text("sucka mcs", ascii2hex($plaintext))), "\n";
}
