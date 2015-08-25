#!/usr/bin/perl -w

#     chal13.pl - ECB cut and paste (Fake server returns encrypted
#     unprivileged object; I craft new ciphertext that decrypts to a
#     privileged object.)
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

use strict;

use Cryptopals qw(random_bytes printhash ascii2hex encryption_oracle
    hex2ascii ascii2hex_blocks);

use Crypt::OpenSSL::AES;
use ProfileParsing;
use BreakECB;

## Give input

my $bill = 'billg@microsoft.com';
my $ciphertext_tame = encrypted_profile_for($bill);

##

print "Probe the encrypted_profile_for() function\n--------\n";
my $blocksize = find_ecb_blocksize(\&encrypted_profile_for);
print "Algorithm block size is :\t** ", $blocksize, " **\n";
my $bigemail = ("hello." x 200) . '@yahoo.com';
print "Algorithm mode is:\t\t** ",
    encryption_oracle(encrypted_profile_for($bigemail)), " **\n";
for my $input ('blah@myisp.com', 'blai@myisp.com') {
    my $output = ascii2hex_blocks(encrypted_profile_for($input), $blocksize);
    print "$input                 -> $output\n";
}
for my $s (0..31) {
    my $input = 'n@h.com' . ("m" x $s);
    my $output = ascii2hex_blocks(encrypted_profile_for($input), $blocksize);
    print "$input", (' ' x (32 - $s)) ," -> $output\n";
}

my $magic_email_M =    'n@h.commmmmmmmmmmmmmmmmmmm'; 
my $magic_email_role = 'n@h.commmm            role'; #grab 2nd block of Ctxt.
print ascii2hex_blocks(encrypted_profile_for($magic_email_role)
		       , $blocksize), "\n";




my $boring_part = 'befc6d0973b6862929c65a5c1a8e5447e1080646088382fd7672b6a2c67e17fe';
my $tame = 'fcaeaa3fe7040c2fa5294821afe2c876';
my $all_m = '17fe8473815bd34304df8525070f5e02';
my $edit = '89d53a9b843bbbe3aa85f0caf17a5f01';

my $ciphertext_nasty = hex2ascii($boring_part . $edit);

##

print "\nDisplay the output\n--------\n";
my %obj_tame = %{decrypt_and_parse($ciphertext_tame)}; #needed for tests
my %obj_nasty = %{decrypt_and_parse($ciphertext_nasty)};
print "Server creates the following tame record:\n";
printhash(%obj_tame);
print "And the following nasty record:\n";
printhash(%obj_nasty);

print "\nFinal result\n--------\n";
if (exists $obj_nasty{'role'} && $obj_nasty{'role'} eq 'admin') {
    print "YOU ARE ELLEET!!!!1!\n";
}
else {
    print "YOU ARE NOT ELEET.\n";
}
print "DONE!\n\n";

# test
die unless $obj_tame{"role"} eq "user" and $obj_tame{"email"} eq $bill;
warn "Passed assertions ($0).\n";
