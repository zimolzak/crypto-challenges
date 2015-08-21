#!/usr/bin/perl -w

# usage: ./emp_hist.pl  /Users/ajz/powerbook/Users/ajz/Documents/1\ Cache-like/800\ -\ Lit/820\ -\ Eng\ lit/austen/1342\ pride.txt

use strict;
use Histogram;
use Cryptopals qw (signature printhash) ;

local $/; #slurp
while(<>){
    my $p = histogram($_);
    my @count = @{$p};
    print_histo(@count);
    print "\n";
    
    my $q = signature($_);
    my %h = %{$q};
    printhash(%h);
}
print "\n";
