#     CBCBitflip.pm - Functions to assist changing 1 bit of a CBC
#     ciphertext, systematic application of same, and analysis of
#     result.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

package CBCBitflip;
use strict;
use warnings;
use Exporter;
use Cryptopals;

our $VERSION = 1;
our @ISA= qw( Exporter );

our @EXPORT_OK = qw( flip_bit );

our @EXPORT = qw( flip_bit magic_nums_cbc);

sub flip_bit {
    my ($str, $bit) = @_;
    die "Bit $bit is out of range$!" if $bit > (length($str)*8);
    my $byte_num = int($bit/8);
    my $byte = substr($str,$byte_num,1);
    my $mask = chr(1 << (7 - ($bit % 8)));
    substr($str,$byte_num,1) = $byte ^ $mask;
    return $str;
}

sub magic_nums_cbc {
    # Takes pointer to infix-type func, and blocksize. Returns how
    # many bytes of junk to feed it to get aligned on a block, plus
    # how many blocks at beginning to throw away.

    # Method: Find the first iteration where there is 1 STATIONARY block.
    
    my ($fp, $blocksize) = @_;
    my ($n, $i);
    my $first_examine_block;
    for $n (($blocksize)..(2 * $blocksize)){
	my @blocks = split_bytes(&$fp("A" x $n), $blocksize);
	my @blocks_next = split_bytes(&$fp("A" x ($n+1)), $blocksize);
	if ($n==$blocksize){
	    for $i (0..($#blocks)) {
		if ($blocks[$i] ne $blocks_next[$i]) {
		    $first_examine_block = $i;
		    last;
		}
	    }
	}
	for $i ($first_examine_block..($#blocks)) {
	    if ($blocks[$i] eq $blocks_next[$i]){
		return (($n - $blocksize), $i);
		# i+1 is the NUMBER (not index) of blocks to
		# remove. Why? See diagram.
		# xxxxxxxx xxxAAAAA AAAAAAAA uuuuuuu_
		# xxxxxxxx xxxAAAAA AAAAAAAA Auuuuuuu
		#     0        1       i=2     i+1=3
		# ...where x is random txt, A is A, and u is target
		# unknown str.
	    }
	}
    }
    # return nothing if fail
}


1;
