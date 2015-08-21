#!/usr/bin/perl -w
use strict;
use Cryptopals qw(key_xor_hex_to_text ascii2hex);

my $plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";

#print ascii2hex($plaintext);

print ascii2hex(key_xor_hex_to_text("ICE", ascii2hex($plaintext))), "\n";

#print key_xor_hex_to_text("A", "70");

for my $plaintext ("Hello", "Testing this", "asdfsdfwef", "Bruce lee was a german swiss physicist.") {
    print "$plaintext\t|\t";
    print key_xor_hex_to_text("sucka mcs", ascii2hex($plaintext)), "\t|\t";
    print ascii2hex(key_xor_hex_to_text("sucka mcs", ascii2hex($plaintext))), "\n";
}
