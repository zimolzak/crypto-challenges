package Histogram;
use strict;
use warnings;
use Exporter;

our $VERSION = 1;

our @ISA= qw( Exporter );

our @EXPORT_OK = qw( histogram print_histo);

our @EXPORT = qw( histogram print_histo);

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

1;
