#     Cryptopals.pm - Assorted coversion and calculation functions for
#     matasano crypto challenges (cryptopals.com).
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

package Cryptopals;
use strict;
use warnings;
use Exporter;

our $VERSION = 1;

our @ISA= qw( Exporter );

our @EXPORT_OK = qw( find_scxor_decrypts printhash hex_xor_hex
    hex2ascii ascii2hex letterfreq sum proportion metric argmax
    key_xor_hex_to_text hamming hex_bits b2h argmin keys_ascending
    ceil signature aes_ecb_decrypt pad_text aes_cbc_decrypt_block);

our @EXPORT = qw( find_scxor_decrypts printhash hex_xor_hex h2b
    signature hamming keys_ascending ceil find_generic_decrypts
    key_xor_hex_to_text);

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
my $spaces = "\r\n ";
my $unprintable;
for (0..9, 11, 12, 14..31, 127) {
    $unprintable .= chr($_);
}

my $misc;
for (33..64, 91..96, 123..126) {
    $misc .= chr($_);
}

die unless (length($letters) * 2)
    + length ($spaces . $unprintable . $misc) == 128;

my %ascii_class;
$ascii_class{"letters"} = $letters;
$ascii_class{"spaces"} = $spaces;
$ascii_class{"misc"} = $misc;
$ascii_class{"unprintable"} = $unprintable;

my $nonletters = chr(0);
for my $val (1 .. 64, 91 .. 96, 123 .. 127){
    $nonletters .= chr($val);
}

my $printable;
for (32 .. 126) {
    $printable .= chr($_);
}

sub metric {
    # Improving this improves your codebreaking! Higher metric means
    # more likely to be English. Remember, PROPORTION() does it
    # case-insensitive (already).

    my $strictly_decreasing = (
	proportion($letters,@_) > proportion($spaces,@_) &&
	proportion($spaces,@_) >= proportion($misc,@_) &&
	proportion($misc,@_) >= proportion($unprintable,@_)
	);
    return proportion($letters, @_) * $strictly_decreasing;
}

sub signature {
    my ($text) = @_;
    my %sig; 
    while(my($k, $v) = each %ascii_class) {
	$sig{$k} = proportion($v, $text);
    }
    return \%sig;
}

sub argmax {
    my @list = @_;
    my @sort_desc = sort {$b<=>$a} @list;
    my @args = grep { $list[$_] == $sort_desc[0] } 0 .. $#list;
    return @args;
}

sub argmin {
    # returns an ARRAY!! In case of ties.
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
    # take actual char string (key), xor it with hex string, return real text.
    my ($char, $hex_in) = @_;
    my $hex_char = ascii2hex($char);
    my $int_repeats = int ((length $hex_in) / (length $hex_char));
    my $extra_chars = (length $hex_in) % (length $hex_char);
    my $repeated_key = $hex_char x $int_repeats
	. substr($hex_char, 0, $extra_chars);

    return hex2ascii(hex_xor_hex($hex_in, $repeated_key));
}

sub find_scxor_decrypts {
    my ($cipher_hex) = @_;
    return find_generic_decrypts($cipher_hex, \&key_xor_hex_to_text);
}

sub find_generic_decrypts {
    # Tries to break a *generic* cipher that uses a single-character
    # key (not given). This function receives the ciphertext in hex
    # and a pointer to a single char decrypt function that does
    # something like the following: decryptor("K", "0105ffdcba") -->
    # "Hello", where "J" is a single letter key that gets repeated.
    # The find_generic_decrypts function makes certain assumptions
    # about how the decryptor function operates.
    my %results;
    my @metrics = (0.0) x 255;
    my ($cipher_hex, $decrypt_func) = @_;
    
    for my $charval (0 .. 255) { # Formerly assuming 32 .. 126 or " " .. "~"
	my $plaintext = &$decrypt_func(chr($charval), $cipher_hex);
	$metrics[$charval] = metric($plaintext);
    } # first pass, check all chars, before storing the best.

    for my $arg (argmax(@metrics)){
	$results{chr($arg)} =
	    &$decrypt_func(chr($arg), $cipher_hex)
	    if $metrics[$arg] > 0;
    }
    return \%results;
}

sub printhash {
    # eats the real thing, not a pointer.
    my $iskey = 1;
    for my $x (@_) {
	if ($iskey){
	    print "  $x -> " ;
	}
	else {
	    $x =~ s/[\r\n\v]//g;
	    if (length($x) > 70){
		print substr($x, 0, 70), "\n";
	    }
	    else {
		print "$x\n";
	    }
	}
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

sub keys_ascending {
    # take pointer, return real array. Return keys with lowest vals.
    my ($p) = @_;
    my %h = %{$p};
    my @a = sort { $h{$a} <=> $h{$b} } keys %h;
    return @a;
}

sub ceil {
    # can use posix instead
    my ($x) = @_;
    return $x if int($x) == $x;
    return int ($x + 1) if $x > 0;
    return int ($x);
}

die unless ceil(3) == 3;
die unless ceil(2.5) == 3;
die unless ceil(-2.5) == -2;

sub aes_ecb_decrypt {
    # note that 2nd arg is cipherTEXT, that is, NOT in hex form.
    my ($keyfrag, $ciphertext) = @_;
    my $l = length($keyfrag);
    my $key;
    if ($l==1 or $l==2 or $l==4 or $l==8 or $l==16){
	$key = $keyfrag x (16/$l);
    }
    else {
	die "I do not know how to feed AES a $l byte key";
    }
    my $aes = new Crypt::OpenSSL::AES($key);
    my $plaintext;
    for (my $i=0; my $block = substr($ciphertext, 16*$i, 16); $i++) {
	$plaintext .= $aes->decrypt($block);
    }
    return $plaintext;
}

sub pad_text {
    my ($block, $blocklength) = @_;
    die "Block is too long" if length($block) > $blocklength;
    return $block . ("\x04" x ($blocklength - length($block) ) );
}

sub aes_cbc_decrypt_block {
    # expects KEY, CIPHER_BLOCK, and IV all in real text, not hex.
    my ($key, $cipher_block, $iv) = @_;
    die "Expected 16 byte key" if length($key)!=16;
    my $aes = new Crypt::OpenSSL::AES($key);
    my $intermediate = $aes->decrypt($cipher_block);
    my $plaintext = hex2ascii(hex_xor_hex(ascii2hex($intermediate),
					  ascii2hex($iv)));
    return $plaintext;
}

1;
