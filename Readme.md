The Matasano crypto challenges
========

48 practical programming exercises using real-world cryptography. For
more information, see http://cryptopals.com/

1. Convert hex to base64
2. Fixed XOR
3. Single-byte XOR cipher
4. Detect single-character XOR
5. Implement repeating-key XOR
6. Break repeating-key XOR
7. AES in ECB mode
8. Detect AES in ECB mode

The ones that use stdin so far: 4, 6, 7, 8. The others carry their
inputs with them. Redirecting 4 to a file is definitely advisable. 6
is "the big one." Takes about 40 sec to run.

To do
----
* Make better use real base64 library - use MIME::Base64;
* ceil() from POSIX
* I installed Crypt::OpenSSL::AES no problem, but Crypt::Mode::ECB
  failed because encode_base64url is not exported by the MIME::Base64
  module. Seems like a version problem. Turns out I didn't need it.

Important conclusion
--------
* Be more accurate about picking the best key size, and about the metric.
