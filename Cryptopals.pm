package Cryptopals;
use strict;
use warnings;
use Exporter;

our $VERSION = 1;

our @ISA= qw( Exporter );

our @EXPORT_OK = qw( find_decrypts printhash hex_xor_hex hex2ascii
letterfreq sum proportion metric argmax key_xor_hex_to_text );

our @EXPORT = qw( find_decrypts printhash hex_xor_hex h2b );

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

sub hex2ascii {
    return pack "H*", @_;
}

sub letterfreq { 
    my @freqs = (0) x 26;
    my ($str) = @_;
    my $i = 0;
    for my $letter ("A" .. "Z") {
	$freqs[$i] = $freqs[$i] + ($str =~ s/$letter/$letter/gi);
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

sub proportion {
    my ($charset, $str) = @_;
    $charset =~ tr/a-z/A-Z/;
    $str =~ tr/a-z/A-Z/;
    my @chars = split(//, $charset);
    my @string = split(//, $str);
    my $found = 0;
    for my $s (@string) {
	for my $c (@chars){
	    $found++ if $s eq $c; # s/// fails with chars like '('
	}
    }
    return $found / (length $str);
}

my $letters = "abcdefghijklmnopqrstuvwxyz";

my $nonletters = chr(0);
for my $val (1 .. 64, 91 .. 96, 123 .. 127){
    $nonletters .= chr($val);
}

sub metric {
    return proportion($letters, @_) * proportion("etaoin", @_);
}

sub argmax {
    my @list = @_;
    my @sort_desc = sort {$b<=>$a} @list;
    my @args = grep { $list[$_] == $sort_desc[0] } 0 .. $#list;
    return @args;
}

sub key_xor_hex_to_text {
    # take actual char string, xor it with hex string, return real text.
    my ($char, $hex_in) = @_;
    my $hex_char = sprintf "%x", ord($char);
    my $repeated_key = $hex_char x ((length $hex_in) / 2);
    return hex2ascii(hex_xor_hex($hex_in, $repeated_key));
}

sub find_decrypts {
    my %results;
    my @metrics = (0.0) x 127;
    my ($cipher_hex) = @_;
    
    for my $charval (32 .. 126) { # " " .. "~"
	my $plaintext = key_xor_hex_to_text(chr($charval), $cipher_hex);
	$metrics[$charval] = metric($plaintext);
    }

    for my $arg (argmax(@metrics)){
	$results{chr($arg)} = key_xor_hex_to_text(chr($arg), $cipher_hex);
    }
    return \%results;
}

sub printhash {
    my $iskey = 1;
    for my $x (@_) {
	print "$x -> " if $iskey;
	print "$x\n" if not $iskey;
	$iskey ^= 1;
    }
}

1;
