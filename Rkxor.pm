#     Rkxor.pm - Functions to assist analysis of a Repeating Key XOR
#     cipher, akin to a Vigenere cipher.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

package Rkxor;
use strict;
use warnings;
use Exporter;
use Cryptopals;
use Histogram;

our $VERSION = 1;

our @ISA= qw( Exporter );

our @EXPORT_OK = qw( break_rk_xor break_cipher_given_keysize);

our @EXPORT = qw( break_rk_xor );

sub hex2blocks {
    my ($cipher_hex, $bytes) = @_;
    my @blocks = ();
    my $m = ceil(length($cipher_hex) / 2 / $bytes); # number of blocks
    for my $i (0 .. $m-1) {
	if ($i < $m-1) { 
	    push @blocks, substr($cipher_hex, $bytes * 2 * $i, 2 * $bytes);
	}
	else { # on last block, grab unlimited to end of string.
	    push @blocks, substr($cipher_hex, $bytes * 2 * $i);
	}
    }
    return @blocks;
}

sub break_rk_xor {
    my ($cipher_hex, $max_key_len) = @_;

    my @keysizelist = (2 .. $max_key_len);
    my %normdistances;

    # 3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and
    # the second KEYSIZE worth of bytes, and find the edit distance.
    
    for my $keysize (@keysizelist){
	my @b = hex2blocks($cipher_hex, $keysize);
	my $avg_dist = ( hamming($b[0],$b[1]) +
			 hamming($b[2],$b[3]) +
			 hamming($b[4],$b[5]) ) / 3;
	$normdistances{$keysize} = $avg_dist / $keysize;
    }

    # 4. The KEYSIZE with the smallest normalized edit distance is
    # probably the right keysize.

    my $N_top_keysizes = 5;
    my @best_key_sizes = keys_ascending(\%normdistances);
    my @keysizes_to_try = @best_key_sizes[0 .. $N_top_keysizes-1];
    break_cipher_given_keysize(\@keysizes_to_try,
			       $cipher_hex, \&key_xor_hex_to_text);
}

sub break_cipher_given_keysize {
    # Works on a generic (abstract) cipher that uses a multi-character
    # key. 3rd argument is a pointer to a single char decrypt function
    # that does the following: decryptor("J", "0105ffdcba01") -->
    # "Hello." Where "J" is a single letter key that gets repeated.
    my ($kspointer, $cipher_hex, $fp) = @_;
    my @keysize_list = @{$kspointer};

    # 5. Break the ciphertext into blocks of KEYSIZE length.

    print "Trying keys of size "
	, join(', ', @keysize_list), ".\n";
    for my $ks (@keysize_list){ # ks is in bytes

	my @blocks = hex2blocks($cipher_hex, $ks);
	print "\nKey size $ks implies $#blocks blocks.\n";

    # 6. Now transpose the blocks:

	my @transposed;
	for my $i (0 .. $ks-1){
	    for my $j (0 .. $#blocks-1) {
		if ($j==0){
		    push @transposed, substr($blocks[$j], $i * 2, 2);
		}
		else {
		    $transposed[$i] .=
			substr($blocks[$j], $i * 2, 2)
			if length($blocks[$j]) >= ($i+1)*2;
		}
	    }
	}

    # 7. Solve each block as if it was single-character cipher.

	my $key_ch_num = 0;
	for (@transposed) {
	    print "ch $key_ch_num =\n";
	    my %decrypts = %{find_generic_decrypts($_, $fp)};
	    printhash(%decrypts);
	    print_sig(%decrypts);
	    $key_ch_num++;
	}
    }
}

1;
