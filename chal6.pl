#!/usr/bin/perl -w
use strict;
use Cryptopals qw(hamming h2b b2h);

die unless hamming("this is a test", "wokka wokka!!!") == 37;

my $h = "ff00abc12";
my $b = h2b($h);
die unless b2h($b) eq $h;

$b = "dsfwqeiufhoisfvuhbiufhwqriufhgikfughuir372ty4u87234tr8wegf87wghe";
$h = b2h($b);
die unless h2b($h) eq $b;

#while(<>){

#}
