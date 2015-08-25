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

Some use stdin; others carry their inputs with them. 4 and 6 each take
about 40 sec to run on my MacBook Pro (OS X, 2.7 GHz Intel Core i7),
and a little longer on my iMac7,1 running Ubuntu. Not all inputs may
be committed to this git repo.

To do
----
* Make better use real base64 library - use MIME::Base64;
* ceil() from POSIX

* I installed Crypt::OpenSSL::AES no problem, but Crypt::Mode::ECB
  failed because encode_base64url is not exported by the MIME::Base64
  module. Seems like a version problem. Turns out I didn't need
  it. Also, OpenSSL::AES requires ssl headers, so sudo apt-get install
  libssl-dev if necessary.

Important conclusion
--------
* Be more accurate about picking the best key size, and about the metric.
