#!/usr/bin/perl -w

#     chal12.pl - ECB cut and paste (key-val parsing)
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

use strict;
use Cryptopals qw(random_bytes printhash ascii2hex encryption_oracle hex2ascii);
use Crypt::OpenSSL::AES;
use ProfileParsing qw( encrypted_profile_for decrypt_and_parse decrypt_and_cheat);
use BreakECB;

# Give input
my $bill = 'billg@microsoft.com';
my $ciphertext_tame = encrypted_profile_for($bill);

# Probe the encrypted_profile_for() function
my $blocksize = find_ecb_blocksize(\&encrypted_profile_for);
print "Algorithm block size is :\t** ", $blocksize, " **\n";
my $bigemail = ("hello." x 200) . '@yahoo.com';
print "Algorithm mode is:\t\t** ",
    encryption_oracle(encrypted_profile_for($bigemail)), " **\n\n";

my $answer = find_unk_str(\&encrypted_profile_for, $blocksize);
print "I think secret string is (in hex): ", ascii2hex($answer), "\n";
print "Actual string is (cheat): ", decrypt_and_cheat($ciphertext_tame), "\n\n";

print "Benign ciphertext: ", ascii2hex($ciphertext_tame), "\n";
my $ciphertext_nasty = hex2ascii('eaebcf8064c50ecc597f63eaea88e07d79401fa25c8ed53447574947bc5c58146d05eb5f3228e733ea3619fb8d102dff');
print "Compromised string (cheat): ", decrypt_and_cheat($ciphertext_nasty), "\n\n";

# Display output
my %obj_tame = %{decrypt_and_parse($ciphertext_tame)}; #needed for tests
print "Server creates the following tame record:\n";
printhash(%obj_tame);
print "And the following nasty record:\n";
printhash(%{decrypt_and_parse($ciphertext_nasty)});
print "DONE!\n\n";

# test
die unless $obj_tame{"role"} eq "user" and $obj_tame{"email"} eq $bill;
warn "Passed assertions ($0).\n";
