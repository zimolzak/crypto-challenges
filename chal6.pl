#!/usr/bin/perl -w
use strict;
use Cryptopals qw(hamming);

die unless hamming("this is a test", "wokka wokka!!!") == 37;

print hamming("this is a test", "wokka wokka!!!");
print "\n";

while(<>){

}
