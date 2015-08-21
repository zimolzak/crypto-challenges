#!/usr/bin/perl -w
# usage: ./chal4.pl 4.txt > out.txt

use strict;
use Cryptopals;

while(<>){
    chomp;
    my %best4line = %{find_decrypts($_)};
    print $_, "\n----\n";
    printhash(%best4line);
    print "\n\n";
}
