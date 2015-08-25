#!/usr/bin/perl -w

#     chal12.pl - ECB cut and paste (key-val parsing)
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

use strict;
use Cryptopals qw(random_bytes printhash ascii2hex);
use Crypt::OpenSSL::AES;
use ProfileParsing;
use BreakECB;

# Give input
my $bill = 'billg@microsoft.com';
my $ciphertext = encrypted_profile_for($bill);

# Probe the encrypted_profile_for() function
my $blocksize = find_ecb_blocksize(\&encrypted_profile_for);
print "Algorithm block size is :\t** ", $blocksize, " **\n";

# Display output
my %obj = %{decrypt_and_parse($ciphertext)};
printhash(%obj);

# test
die unless $obj{"role"} eq "user" and $obj{"email"} eq $bill;
warn "Passed assertions ($0).\n";
