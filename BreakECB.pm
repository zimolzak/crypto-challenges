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

our @EXPORT_OK = qw( find_ecb_blocksize find_char find_unk_str
    magic_nums_of_infix find_str_infix);

our @EXPORT = qw( find_ecb_blocksize find_char find_unk_str
    magic_nums_of_infix find_str_infix infix2prepend);

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

    for my $charnum (0..255) {
	my $str_to_feed = ($shortblock . $known_text . (chr $charnum));
	# print "stf $str_to_feed \n";#dm
	my $output_of_long = substr(&$fp($str_to_feed)
				    , 0
				    , $blocksize * $blocks_to_take);
	return (chr $charnum) if $output_of_short eq $output_of_long;
    }
    return undef; # if fail
}

sub find_unk_str {
    # Returns ALL chars of an unknown string, given: 1. pointer to a
    # "prepender" type func that takes string & returns string, 2.
    # block size of the encryptor
    my ($fp, $blocksize) = @_;
    my $total_string = "";
    while(defined(my $c = find_char($fp, $blocksize, $total_string))){
	$total_string .= $c;
    }
    $total_string =~ s/\x04+$//g;
    return $total_string;
}

sub magic_nums_of_infix {
    # Takes pointer to infix-type func, and blocksize. Returns how
    # many bytes of junk to feed it to get aligned on a block, plus
    # how many blocks at beginning to throw away.
    my ($fp, $blocksize) = @_;
    my ($n, $i);
    for $n ($blocksize..(3 * $blocksize)){ 
	my @blocks = split_bytes(&$fp("A" x $n), $blocksize);
	for $i (0..($#blocks-1)) {
	    if ($blocks[$i] eq $blocks[$i+1]){
		return (($n - $blocksize), $i+2);
		# Why i+2? See diagram:
		# xxxAAAAA AAAAAAAA AAAAAAAA uuuuuuu
		#             i        i+1
		# where x is random, A is A, and u is unknown str.
	    }
	}
    }
    # return nothing if fail
}

sub find_str_infix {
    # Takes pointer to infix-type func, and blocksize. Turns it into a
    # prepend-type func. Returns target string.
    my ($fp, $blocksize) = @_;
    my ($bytes_of_junk, $blocks_to_trash) =
	magic_nums_of_infix($fp, $blocksize);
    print "I know $bytes_of_junk $blocks_to_trash \n";#dm
    my $pp = sub {
	#print "I too know $bytes_of_junk $blocks_to_trash $fp \n";#dm
	my ($known_plaintext) = @_;
	my $long_ciphertext = &$fp(("A" x $bytes_of_junk) . $known_plaintext);
	my @blocks = split_bytes($long_ciphertext, $blocksize);
	#print ':', ascii2hex_blocks($long_ciphertext, 16), "\n";#dm
	#print "len ", length($long_ciphertext), '=>', $#blocks, "\n";#dm
	return join('', @blocks[($blocks_to_trash-1)..$#blocks]);
    };
    print "fc -", find_char($pp, $blocksize, ""), "-\n";#dm
    return find_unk_str($pp, $blocksize);
}

sub infix2prepend {
    # Takes pointer to infix-type func, and blocksize. Turns it into a
    # prepend-type func. Returns pointer.
    my ($fp, $blocksize) = @_;
    my ($bytes_of_junk, $blocks_to_trash) =
	magic_nums_of_infix($fp, $blocksize);
    print "res $bytes_of_junk $blocks_to_trash \n";
    my $pp = sub {
	#print "I too know $bytes_of_junk $blocks_to_trash $fp \n";#dm
	my ($known_plaintext) = @_;
	my $long_ciphertext = &$fp(("F" x $bytes_of_junk) . $known_plaintext);
	my @blocks = split_bytes($long_ciphertext, $blocksize);
	#print ':', ascii2hex_blocks($long_ciphertext, 16), "\n";#dm
	#print "len ", length($long_ciphertext), '=>', $#blocks, "\n";#dm
	return join('', @blocks[($blocks_to_trash-1)..$#blocks]);
    };
    return $pp;
}

1;
