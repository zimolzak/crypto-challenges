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

our @EXPORT_OK = qw( find_ecb_blocksize find_char);

our @EXPORT = qw( find_ecb_blocksize find_char);

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

sub find_char {
    # Returns NEXT char of an unknown string, given: 1. pointer to a
    # "prepender" type func that takes string & returns string, 2.
    # block size of the encryptor, 3. Currently known chars.
    my ($fp, $blocksize, $known_text) = @_;

    my $lkt = length($known_text);
    my $blocks_to_take = ceil( ($lkt + 1) / $blocksize);
    my $num_chars = ($blocksize * $blocks_to_take - 1 - $lkt) % $blocksize;

    my $shortblock = ("A" x $num_chars );
    my $output_of_short = substr(&$fp($shortblock), 0, $blocksize * $blocks_to_take);

    for (0..255) {
	my $str_to_feed = ($shortblock . $known_text . (chr $_));
	my $output_of_long = substr(&$fp($str_to_feed), 0, $blocksize * $blocks_to_take);
	
	return (chr $_) if $output_of_short eq $output_of_long;
    }
}

1;
