#     BreakECB.pm - Functions to assist analysis of ECB cipher.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

package BreakECB;
use strict;
use warnings;
use Exporter;
use Cryptopals;

our $VERSION = 1;

our @ISA= qw( Exporter );

our @EXPORT_OK = qw( find_ecb_blocksize );

our @EXPORT = qw( find_ecb_blocksize );

sub find_ecb_blocksize {
    # Expects its arg to be pointer to a func that takes string &
    # returns string.
    my ($fp) = @_;
    my $last_len = length(&$fp("A"));
    my $num_steps = 0;
    my $blocksize = 0;
    for my $num_chars (2..32){
	my $len =  length(&$fp("A" x $num_chars));
	if ($len > $last_len){
	    $num_steps++;
	    $last_len = $len;
	}
	$blocksize++ if $num_steps == 1;
	last if $num_steps == 2;
    }
    return $blocksize;
}


1;
