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
25. Break "random access read/write" AES CTR
26. CTR bitflipping
27. Recover the key from CBC with IV=Key
28. Implement a SHA-1 keyed MAC
29. Break a SHA-1 keyed MAC using length extension
30. Break an MD4 keyed MAC using length extension
31. Implement and break HMAC-SHA1 with an artificial timing leak
32. Break HMAC-SHA1 with a slightly less artificial timing leak
33. Implement Diffie-Hellman
34. Implement MITM key-fixing attack on D-H with parameter injection
35. DH with negotiated groups, and break with malicious "g" parameters
36. Implement Secure Remote Password (SRP)
37. Break SRP with a zero key
38. Offline dictionary attack on simplified SRP
39. Implement RSA
40. Implement an E=3 RSA Broadcast attack
41. Implement unpadded message recovery oracle
42. Bleichenbacher's e=3 RSA Attack
43. DSA key recovery from nonce
44. DSA nonce recovery from repeated nonce
45. DSA parameter tampering
46. RSA parity oracle
47. Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)
48. Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)

Challenge 1-8 are basics. Then 9-16, 17-24, and 25-32 deal mainly with
block ciphers. After that it gets into number-theoretic methods.

I went to Python starting with #17, just for fun & experience.

Some of my implementations use stdin; others carry their inputs with
them or open a filename hard-coded in. A couple input files are
"handcrafted:" `unknown_key.txt` came from random.org, and `17.txt`
was cut and pasted from http://cryptopals.com/sets/3/challenges/17 . I
decided to commit *most* of the input files to this repo, with the
exception of `8.txt` because it's big.

Times noted in makefile are from MacBook Pro (8,1 early 2011, OS X,
2.7 GHz Intel Core i7), or iMac7,1 (Intel Core 2 Duo, 2.0-2.4 GHz
circa 2007) running Ubuntu.

Conclusions / insights
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

* Chosen plaintext attacks are everywhere.

* Don't seed a RNG off of the current UNIX time in seconds.

* Don't use the key as the IV; IV is trivially recoverable.

* So what are CBC and CTR good for?

* Wow, web.py makes it *really* easy to roll a tiny app, even for
  someone who has never done any web programming.

* 8 milliseconds per character in a string-compare is breakable. 7 ms
  is breakable with manual help. Specifically, set T to 6 and fill in
  some text from some replicates. This all feels a *lot* like DNA
  sequencing. 6 ms similarly; set T to 5 ms, fill in by hand. I can
  break 4ms by an automated try-try-again and tracking the longest
  guess on record. 3.7 ms is a good threshold for that. Probably will
  require some sort of voting, graphics, and/or statistics to get
  lower than that. Signal to noise is going to decrease toward the end
  of the string. Averaging seems to allow me to bring down T and the
  back-up parameter. Also this results in thousands and thousands of
  server requests: something like 100 per character of the hash. It is
  somewhat cheating to know in advance what is the server's delay. I
  can break 3.5 ms with no help, with T=3.0, backup=1, and N=10
  replicates of each timing measurement! Probably helps to have the
  server as quiet as possible in terms of CPU.

* Diffie-Hellman parameter injection feels weird and kind of hard to
  understand or unrealistic?

* I am surprised that my offline dictionary attack on SRP with a
  stolen hash (HMAC) doesn't go faster. See `chal38.py` or `srp.py`,
  class `Server` when `mitm=True`, specifically method
  `validate_hash()`. Only 50 - 60 guesses per second?

* SRP with zero key is indeed fun.

* RSA implementation and several of the challenges about it were fun.

* RSA without padding is bad. RSA that doesn't fully check for proper
  padding or other compliance is also bad.

* Once again, don't reuse your nonce, hence the name. When it comes to
  DSA, I guess you can't even give it away or make it easy to guess?

* Don't provide a mechanism to give away even one bit of your RSA
  plaintext. Not in error messages, not in any way. Seriously. And if
  you use an implementation written by someone who accidentally does
  provide such a mechanism, then everything's ruined if Mallory finds
  this mechanism.

* When translating intricate paper methods to code, it helps to do it
  first using a toy case that runs really fast. Also, I finally
  graduated from Print Statement High School and matriculated as a
  freshman at Debugger University.
