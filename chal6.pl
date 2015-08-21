#!/usr/bin/perl -w
# usage ./chal6.pl 6.txt

use strict;
use Cryptopals qw(hamming h2b b2h ascii2hex keys_ascending);

# use MIME::Base64;

#tests

die unless hamming(ascii2hex("this is a test"),
		   ascii2hex("wokka wokka!!!")) == 37;
my $cipher_hex = "ff00abc12";
my $b = h2b($cipher_hex);
die unless b2h($b) eq $cipher_hex;
$b = "dsfwqeiufhoisfvuhbiufhwqriufhgikfughuir372ty4u87234tr8wegf87wghe";
$cipher_hex = b2h($b);
die unless h2b($cipher_hex) eq $b;


# main

$b = "";
while(<>){
    chomp;
    $b .= $_
}
$cipher_hex = b2h($b);

my @keysizelist = (2 .. 40);
my %normdistances;

for my $keysize (@keysizelist){
    my $first = substr($cipher_hex, 0, 2*$keysize);
    my $second = substr($cipher_hex, 2*$keysize, 2*$keysize);
    $normdistances{$keysize} = hamming($first,$second) / $keysize;
}

my @best_key_sizes = keys_ascending(\%normdistances);

print join(', ', @best_key_sizes[0 .. 2]), "\n";

my $N_top_keysizes = 3;

$cipher_hex = "aabbccAABBCC112233"; #deleteme

for my $ks (@best_key_sizes[0 .. ($N_top_keysizes - 1)]){
    my @single_char_xors;
    for my $i (0..$ks){
	for(my $j = 0;
	    my $contents = substr($cipher_hex, $ks * 2 * $j + 2 * $i, 2);
	    $j++){
	    $single_char_xors[$i] .= $contents;
	}
    }
    print "$ks ", join(':',@single_char_xors), "\n";
}
