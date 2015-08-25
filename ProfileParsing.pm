#     ProfileParsing.pm - Functions to simulate encode/decode of
#     cookies on web site.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

package ProfileParsing;
use strict;
use warnings;
use Exporter;
use Cryptopals qw(aes_ecb pad_multiple);

our $VERSION = 1;
our @ISA= qw( Exporter );

our @EXPORT_OK = qw( encrypted_profile_for decrypt_and_parse);

our @EXPORT = qw( encrypted_profile_for decrypt_and_parse);

sub parse_cookie {
    #returns hashref
    my ($str) = @_;
    my %hash;
    for (split(/&/, $str)) {
	my ($k, $v) = split(/=/);
	$hash{$k} = $v;
    }
    return \%hash;
}

sub profile_for {
    my ($email) = @_;
    $email =~ s/[&=]/./g; # Take that, hax0rs. [Or so you THINK.]
    return "email=" . $email . "&uid=" . int(rand(100000)) . "&role=user";
}

sub encrypted_profile_for {
    my ($email, $key) = @_;
    my $padded_cookie = pad_multiple(profile_for($email), length($key));
    return aes_ecb($key, $padded_cookie, "enc");
}

sub decrypt_and_parse {
    # returns hashref
    my ($ciphertext, $key) = @_;
    my $plaintext = aes_ecb($key, $ciphertext, "dec");
    $plaintext =~ s/\x04//g;
    return parse_cookie($plaintext);
}

1;
