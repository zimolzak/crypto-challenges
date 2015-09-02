The Matasano crypto challenges
========

48 practical programming exercises using real-world cryptography.

A good way to test them all is `make > /dev/null`.

For more information, see http://cryptopals.com/

1. Convert hex to base64
2. Fixed XOR
3. Single-byte XOR cipher
4. Detect single-character XOR
5. Implement repeating-key XOR
6. Break repeating-key XOR
7. AES in ECB mode
8. Detect AES in ECB mode
9. Implement PKCS#7 padding
10. Implement CBC mode
11. An ECB/CBC detection oracle
12. Byte-at-a-time ECB decryption (Simple)
13. ECB cut-and-paste
14. Byte-at-a-time ECB decryption (Harder)
15. PKCS#7 padding validation
16. CBC bitflipping attacks
17. CBC padding oracle
18. Implement CTR
19. Fixed-nonce CTR using substitutions
20. Fixed-nonce CTR using statistics
21. Implement MT19937
22. Get MT19937 seed
23. Clone a MT19937
24. MT19937 stream cipher

Challenge 1-8 are basics. Then 9-16, 17-24, and 25-32 deal mainly with
block ciphers. After that it gets into number-theoretic methods.

I went to Python starting with #17, just for fun & experience.

Some of my implementations use stdin; others carry their inputs with
them or open a filename hard-coded in. A couple input files are
"handcrafted:" `unknown_key.txt` came from random.org, and `17.txt`
was cut and pasted from http://cryptopals.com/sets/3/challenges/17 . I
decided to commit *most* of the input files to this repo, with the
exception of `8.txt` because it's big.

4 and 6 each take about 40 sec to run on my MacBook Pro (OS X, 2.7 GHz
Intel Core i7), and a little longer on my iMac7,1 running Ubuntu.
Number 20 takes about 20 seconds.

Important conclusions
--------

* When analyzing repeating-key XOR, be more accurate about picking the
  best key size, and about the metric (for evaluating whether putative
  plaintext fits English letter distributions).

* ECB cut-and-paste: had to figure out "user\x04\x04.." which allowed
  finding "...role=". Then had to figure out "admin\x04\x04.."

* ECB decryption: Once you align on a block, it's somewhat simple
  comparing (short block + unknown char) to (short block + try each
  known char).

* CBC bitflip (inserts into CBC): Know where your initial string lies
  within the block. Then know how to flip your initial string into
  your final string.

* CBC padding (decrypts CBC): It helped to write some pseudocode
  first, but I still had to be very careful with the arithmetic. Don't
  guess \x01 as the last char, or else the last block will always
  falsely show up with valid padding, ruining the rest of the
  last-block guesses. Instead skip to \x02; it's very unlikely
  (1/65,536) to see a real block ending in \x02\x02 even in line-noise
  type plaintext. Less likely still in a natural language.
