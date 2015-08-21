package Cryptopals;
use strict;
use warnings;
use Exporter;

our $VERSION = 1;

our @ISA= qw( Exporter );

our @EXPORT_OK = qw( find_decrypts printhash hex_xor_hex hex2ascii ascii2hex
letterfreq sum proportion metric argmax key_xor_hex_to_text hamming hex_bits b2h argmin);

our @EXPORT = qw( find_decrypts printhash hex_xor_hex h2b );

# construct table
our @b64table;
for my $x ("A" .. "Z") {push @b64table, $x;}
for my $x ("a" .. "z") {push @b64table, $x;}
for my $x ("0" .. "9") {push @b64table, $x;}
push @b64table, "+";
push @b64table, "/";

sub h2b {
    # hex to base64. 3 hex chars --> 4 octal --> 2 base64.
    my ($str) = @_;
    my $returnme = " ";
    for (my $i = 0; $i < length $str; $i += 3){
	my $threehex = substr($str, $i, 3);
	my $octal = sprintf "%04o", (hex $threehex);
	my $idx1 = oct(substr($octal, 0, 2));
	my $idx2 = oct(substr($octal, 2, 2));
	$returnme = $returnme . $Cryptopals::b64table[$idx1] . $Cryptopals::b64table[$idx2];
    }
    $returnme =~ s/ //g;
    return $returnme;
}

sub b2h {
    # every two base64 chars to three hex chars
    my ($str) = @_;
    my $returnme = " ";
    for (my $i = 0; $i < length $str; $i += 2){
	# does not handle equal sign padding! FIX ME!
	next if substr($str, $i, 1) eq "=" or substr($str, $i+1, 1) eq "=";
	my @idx1 = arg(substr($str, $i, 1), \@Cryptopals::b64table);
	my @idx2 = arg(substr($str, $i+1, 1), \@Cryptopals::b64table);
	my $val = ($idx1[0] << 6) + $idx2[0];
	my $deleteme = substr($str, $i, 1);
	$returnme .= sprintf "%03x", $val;
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

sub hex_bits {
    #  return number of bits set in a hex string
    my ($hex) = @_;
    my $bits_set = 0;
    for (my $i = 0; $i < length $hex; $i++){
	my @bits = split(//, sprintf "%b", hex substr($hex, $i, 1));
	$bits_set += sum(@bits);
    }
    return $bits_set;
}

sub hex2ascii {
    return pack "H*", @_;
}

sub ascii2hex {
    my ($str) = @_;
    return unpack "H*", $str;
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

sub argmin {
    # returns an ARRAY!!
    my @list = @_;
    my @sort_desc = sort {$a<=>$b} @list;
    my @args = grep { $list[$_] == $sort_desc[0] } 0 .. $#list;
    return @args;
}

sub arg {
    ## IMPORTANT! Takes a value AND an array POINTER, and does STRING compare.
    my ($val, $listptr) = @_;
    my @list = @{$listptr};
    my @args = grep { $list[$_] eq $val } 0 .. $#list;
    return @args;    
}

sub key_xor_hex_to_text {
    # take actual char string, xor it with hex string, return real text.
    my ($char, $hex_in) = @_;
    my $hex_char = ascii2hex($char);
    my $int_repeats = int ((length $hex_in) / (length $hex_char));
    my $extra_chars = (length $hex_in) % (length $hex_char);
    my $repeated_key = $hex_char x $int_repeats . substr($hex_char, 0, $extra_chars);

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

sub hamming {
    #  takes two equal-length buffers (strings) and returns bitwise
    #  edit distance.
    my ($str1, $str2) = @_;
    die if (length $str1) != (length $str2);
    return hex_bits(hex_xor_hex($str1, $str2));
}

1;
