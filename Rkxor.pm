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
    my ($cipher_hex,  $max_key_len) = @_;

    my @keysizelist = (2 .. $max_key_len);
    my %normdistances;

    # 3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and
    # the second KEYSIZE worth of bytes, and find the edit distance.
    
    for my $keysize (@keysizelist){
	my @b = hex2blocks($cipher_hex, $keysize);
	my $avg_dist = ( hamming($b[0],$b[1]) + hamming($b[2],$b[3]) + hamming($b[4],$b[5]) ) / 3;
	$normdistances{$keysize} = $avg_dist / $keysize;
    }

    # 4. The KEYSIZE with the smallest normalized edit distance is
    # probably the key.

    my @best_key_sizes = keys_ascending(\%normdistances);

    print "Trying keys of size ", join(', ', @best_key_sizes[0 .. 2]), ".\n";

    my $N_top_keysizes = 3;

    for my $ks (@best_key_sizes[0 .. ($N_top_keysizes - 1)]){ # ks is in bytes

	# 5. Break the ciphertext into blocks of KEYSIZE length.

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
		    $transposed[$i] .= substr($blocks[$j], $i * 2, 2) if length($blocks[$j]) >= ($i+1)*2;
		}
	    }
	}

	# 7. Solve each block as if it was single-character XOR.

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
