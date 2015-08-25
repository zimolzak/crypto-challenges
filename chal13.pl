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

my $bill = 'billg@microsoft.com';

print profile_for($bill), "\n";

my $key = random_bytes(16);

my $ciphertext = encrypted_profile_for($bill, $key);

print ascii2hex($ciphertext), "\n";

printhash(%{decrypt_and_parse($ciphertext, $key)});

warn "Passed assertions ($0).\n";
