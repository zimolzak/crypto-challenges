#!/usr/bin/perl -w
# usage ./chal6.pl 6.txt

use strict;
use Cryptopals qw(hamming h2b b2h ascii2hex keys_ascending ceil);

# use MIME::Base64;

#tests

die unless hamming(ascii2hex("this is a test"),
		   ascii2hex("wokka wokka!!!")) == 37;
my $cipher_hex = "ff00abc12";
my $b = h2b($cipher_hex);
die unless b2h($b) eq $cipher_hex;
$b = "dsfwqeiufhoisfvuhbiufhwqriufhgikfughuir372ty4u87234tr8wegf87wghe";
$cipher_hex = b2h($b);
die unless h2b($cipher_hex) eq $b;


# main

$b = "";
while(<>){
    chomp;
    $b .= $_
}
$cipher_hex = b2h($b);

my @keysizelist = (2 .. 40);
my %normdistances;

for my $keysize (@keysizelist){
    my $first = substr($cipher_hex, 0, 2*$keysize);
    my $second = substr($cipher_hex, 2*$keysize, 2*$keysize);
    $normdistances{$keysize} = hamming($first,$second) / $keysize;
}

my @best_key_sizes = keys_ascending(\%normdistances);

print join(', ', @best_key_sizes[0 .. 2]), "\n";

my $N_top_keysizes = 3;

$cipher_hex = "aabbccAABBCC112233"; #deleteme

for my $ks (@best_key_sizes[0 .. ($N_top_keysizes - 1)]){
    # ks is in bytes, not hex characters

    # break the ciphertext into blocks of KEYSIZE length.
    my @blocks = ();
    my $m = ceil(length($cipher_hex) / 2 / $ks); # number of blocks
    print "ks $ks so $m blocks.\n";
    for my $i (0 .. $m-1) {
	if ($i < $m-1) { 
	    push @blocks, substr($cipher_hex, $ks * 2 * $i, 2 * $ks);
	}
	else {
	    # on last block, grab unlimited to end of string.
	    push @blocks, substr($cipher_hex, $ks * 2 * $i);
	}
    }
    print join(':',@blocks), "\n";

    # Now transpose the blocks:
    my @transposed;
    for my $i (0 .. $ks-1){
	for my $j (0 .. $m-1) {
	    if ($j==0){
		push @transposed, substr($blocks[$j], $i * 2, 2);
	    }
	    else {
		$transposed[$i] .= substr($blocks[$j], $i * 2, 2);
		# Don't need to check len(b_j) because substr is OK?
	    }
	}
    }
    print "  T: ", join(':',@transposed), "\n";

    # Solve each block as if it was single-character XOR.
    
}
