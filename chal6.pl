#!/usr/bin/perl -w
# usage ./chal6.pl 6.txt

use strict;
use Cryptopals qw(hamming h2b b2h ascii2hex argmin argmax printhash);

# use MIME::Base64;

#tests

die unless hamming(ascii2hex("this is a test"),
		   ascii2hex("wokka wokka!!!")) == 37;
my $h = "ff00abc12";
my $b = h2b($h);
die unless b2h($b) eq $h;
$b = "dsfwqeiufhoisfvuhbiufhwqriufhgikfughuir372ty4u87234tr8wegf87wghe";
$h = b2h($b);
die unless h2b($h) eq $b;


# main

$b = "";
while(<>){
    chomp;
    $b .= $_
}
$h = b2h($b);

my @keysizelist = (2 .. 40);
my %normdistances;

for my $keysize (@keysizelist){
    my $first = substr($h, 0, 2*$keysize);
    my $second = substr($h, 2*$keysize, 2*$keysize);
    $normdistances{$keysize} = hamming($first,$second) / $keysize;
}

printhash %normdistances;

# print join(" ", @normdistances), "\n";
# die unless $#keysizelist == $#normdistances;

# my @am = argmin(@normdistances);
# my $ks = $keysizelist[$am[0]];

# print "Arg $am[0], key size $ks.\n"
