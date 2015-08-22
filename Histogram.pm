#     Histogram.pm - Functions for calculating distributions of
#     characters in a text.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

package Histogram;
use strict;
use warnings;
use Exporter;
use Cryptopals;

our $VERSION = 1;

our @ISA= qw( Exporter );

our @EXPORT_OK = qw( histogram print_histo print_sig);

our @EXPORT = qw( histogram print_histo print_sig);

my $N = 128; # number of ascii chars

sub histogram {
    my ($text) = @_;
    my @count = (0) x $N;
    my @proportion = (0.0) x $N;
    my @text = split(//, $text);
    for my $val (0 .. $N-1) {
	for my $t (@text) {
	    if ($t eq chr($val)){
		$count[$val]++;
		$proportion[$val] += 1 / $#text;
	    }
	}
    }
    return \@count;
}

my $N_COL = 8; # how many columns in the layout

sub print_histo {
    my @hist = @_;
    for my $row (0 .. ($N/$N_COL)-1) {
	for my $col (0 .. $N_COL-1) {
	    my $val = $row * 8 + $col;
	    print "$val\t";
	}
	print "\n";
	for my $col (0 .. $N_COL-1) {
	    my $el = $hist[$row * 8 + $col];
	    print "$el\t";
	}
	print "\n\n";
    }
}

sub print_sig {
    # instead of printing hash, prints the keys & the 4-num sigs of
    # the vals.
    my $iskey = 1;
    for my $x (@_) {
	if ($iskey) {
	    print "  $x -> ";
	}
	else {
	    my %h = %{signature($x)};
	    for my $key qw (letters spaces misc unprintable){ # do it in order
		printf '%.3f ', $h{$key};
	    }
	    print "\n";
	}
	$iskey ^= 1;
    }
}

1;
