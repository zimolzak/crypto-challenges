#!/usr/bin/perl -w
# usage: ./parse_pwd.pl ~/Downloads/10-million-combos.txt > deleteme.txt
# About 6 seconds.

# ./parse_pwd.pl ~/Downloads/10-million-combos.txt | sort | uniq -c |
# sort -nr | head -n 25000 | perl -pe 's/.* //' > final.txt

use strict;
while(<>){
    next unless $. % 10 == 0; # sample every 10 lines
    next if /[\x7f-\xff]/;
    s/.*\t//;
    s/\r//g;
    print;
}
