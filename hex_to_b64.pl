#!/usr/bin/perl 

# Take string of hex chars and output string of base64 chars.

use strict;

# construct table
my @b64table;
for my $x ("A" .. "Z") {push @b64table, $x;}
for my $x ("a" .. "z") {push @b64table, $x;}
for my $x ("0" .. "9") {push @b64table, $x;}
push @b64table, "+";
push @b64table, "/";

sub h2b {
    my ($str) = @_;
    my $returnme = " ";
    for (my $i = 0; $i < length $str; $i += 3){
	my $threehex = substr($str, $i, 3);
	my $octal = sprintf "%04o", (hex $threehex);
	my $idx1 = oct(substr($octal, 0, 2));
	my $idx2 = oct(substr($octal, 2, 2));
	$returnme = $returnme . $b64table[$idx1] . $b64table[$idx2];
    }
    $returnme =~ s/ //g;
    return $returnme;
}

print "TEST " . h2b("4d616e") . "\n";
print "Challenge 1 b64: ";
print h2b("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") . "\n";

sub hex_xor_hex {
    #  takes two equal-length buffers and produces their XOR combination
    my ($buf1, $buf2) = @_;
    die if (length $buf1) != (length $buf2);
    my $returnme = " ";
    for (my $i = 0; $i < length $buf1; $i++){
	# loop one char at a time or else hex overflow
	my $value = ((hex substr($buf1, $i, 1)) ^ (hex substr($buf2, $i, 1)));
	$returnme = $returnme . sprintf "%x", $value;
    }
    $returnme =~ s/ //g;
    return $returnme;
}

print "Challenge 2 XOR result: ";

print hex_xor_hex("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965") . "\n";





# find single char, XOR it against ciphertext, score english plaintext.

print "Challenge 3 ";

my $ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

sub hex2ascii {
    return pack "H*", @_;
}

sub letterfreq {
    my @freqs = (0) x 26;
    my ($str) = @_;
    my $i = 0;
    for my $letter ("A" .. "Z") {
	$freqs[$i] =  $freqs[$i] + ($str =~ s/$letter/$letter/gi);
	$i++;
    }
    return @freqs;
}

sub sum {
    my $total = 0;
    for my $x (@_) {
	$total += $x;
    }
    return $total;
}

print "CIPH: " . (hex2ascii $ciphertext) . "\n" ;

print "  ";
for my $letter ("A" .. "Z") {
    print $letter;
}
print "\n";

for my $charval (32 .. 126) { # " " .. "~"
    my $single_char = chr($charval);
    my $hex_char = sprintf "%x", $charval;
    my $repeated_key = $hex_char x ((length $ciphertext) / 2);
    my $plaintext = hex2ascii(hex_xor_hex($ciphertext, $repeated_key));
    my @f = letterfreq($plaintext);
    if ( (sum(@f) / (length($ciphertext) / 2)) > 0.75 ) {
	print $single_char . " ";
	print @f;
	print " " . sum(@f) . " " . sum(@f) / (length($ciphertext) / 2)  . " " . $plaintext . "\n";
    }
}
