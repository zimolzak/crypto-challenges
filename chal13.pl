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

$blocksize = 16; # Force this because rarely it guesses wrong, but
		 # attacker would have determinted it statistically
		 # anyway.

my $bigemail = ("hello." x 200) . '@yahoo.com';
print "Algorithm mode is:\t\t** ",
    encryption_oracle(encrypted_profile_for($bigemail)), " **\n";
for my $input ('blah@myisp.com', 'blai@myisp.com') {
    my $output = ascii2hex_blocks(encrypted_profile_for($input), $blocksize);
    print "$input   -> $output\n";
}

for my $s (0..11) {
    my $input = ("A" x $s) . "admin" . ("\x04" x 32);
    my $output = ascii2hex_blocks(encrypted_profile_for($input), $blocksize);
    print "$input", (' ' x (11 - $s)) ," -> $output\n";
}

my $boring_part = 'befc6d0973b6862929c65a5c1a8e5447e1080646088382fd7672b6a2c67e17fe';
my $tame = 'fcaeaa3fe7040c2fa5294821afe2c876';
my $flip_one = 'fcaeaa3fe7040c2fa5294821afe2c877';
my $all_m = '17fe8473815bd34304df8525070f5e02';
my $space_space_role = '89d53a9b843bbbe3aa85f0caf17a5f01';
my $user_pad = '6746f4c39e74956b7635f0b1bc1c2d5a';
my $something_role_equals = 'dd18eca8bf9ea4da51552717796d4a42';
my $admin_pad = 'c1465fe69b28abc8515790dab0c4ffbf';

my $ciphertext_nasty = hex2ascii($boring_part
				 . $something_role_equals
				 . $admin_pad);

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
    die;
}
print "DONE!\n\n";

# test
die unless $obj_tame{"role"} eq "user" and $obj_tame{"email"} eq $bill;
warn "Passed assertions ($0).\n";
