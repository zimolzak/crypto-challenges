package Rkxor;
use strict;
use warnings;
use Exporter;
use Cryptopals;
use Histogram;

our $VERSION = 1;

our @ISA= qw( Exporter );

our @EXPORT_OK = qw( break_rk_xor );

our @EXPORT = qw( break_rk_xor );

sub break_rk_xor {
    my ($cipher_hex,  $max_key_len) = @_;

    my @keysizelist = (2 .. $max_key_len);
    my %normdistances;

    for my $keysize (@keysizelist){
	my $first = substr($cipher_hex, 0, 2*$keysize);
	my $second = substr($cipher_hex, 2*$keysize, 2*$keysize);
	$normdistances{$keysize} = hamming($first,$second) / $keysize;
    }

    my @best_key_sizes = keys_ascending(\%normdistances);

    print "Trying keys of size ", join(', ', @best_key_sizes[0 .. 2]), ".\n";

    my $N_top_keysizes = 3;

# $cipher_hex = "aabbccAABBCC112233";

    for my $ks (@best_key_sizes[0 .. ($N_top_keysizes - 1)]){
	# ks is in bytes, not hex characters

	# break the ciphertext into blocks of KEYSIZE length.
	my @blocks = ();
	my $m = ceil(length($cipher_hex) / 2 / $ks); # number of blocks
	print "\nKey size $ks implies $m blocks.\n";
	for my $i (0 .. $m-1) {
	    if ($i < $m-1) { 
		push @blocks, substr($cipher_hex, $ks * 2 * $i, 2 * $ks);
	    }
	    else {
		# on last block, grab unlimited to end of string.
		push @blocks, substr($cipher_hex, $ks * 2 * $i);
	    }
	}
	# print join(':',@blocks), "\n";

	# Now transpose the blocks:
	my @transposed;
	for my $i (0 .. $ks-1){
	    for my $j (0 .. $m-1) {
		if ($j==0){
		    push @transposed, substr($blocks[$j], $i * 2, 2);
		}
		else {
		    $transposed[$i] .= substr($blocks[$j], $i * 2, 2) if length($blocks[$j]) >= ($i+1)*2;
		    # Don't need to check len(b_j) because substr is OK?
		}
	    }
	}
	# print "  T: ", join(':',@transposed), "\n";

	# Solve each block as if it was single-character XOR.
	my $key_ch_num = 0;
	for (@transposed) {
	    print "ch $key_ch_num =\n";
	    my %decrypts = %{find_decrypts($_)};
	    printhash(%decrypts);
	    print_sig(%decrypts);
	    $key_ch_num++;
	}
    }
}

1;
