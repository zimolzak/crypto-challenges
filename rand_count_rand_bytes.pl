#!/usr/bin/perl -w

#     rand_count_rand_bytes.pl - Generate random count of random
#     bytes. Point is to do it one time, and store it in a file, for
#     later repeated consistent use by challenge 14.
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>
#     Full notice is found in the file 'LICENSE' in the same directory
#     as this file.

# usage: ./rand_count_rand_bytes.pl > rand_bytes.txt

use strict;
use Cryptopals qw(random_bytes);

my $n = int(rand(54)+10);
print random_bytes($n);
