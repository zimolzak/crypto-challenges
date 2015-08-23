test : 4.txt 6.txt quicktest
	./chal4.pl 4.txt > /dev/null
	./chal6.pl 6.txt

quicktest : 7.txt 8.txt 10.txt
	./chal1.pl
	./chal2.pl
	./chal3.pl
	./chal5.pl
	./chal7.pl 7.txt
	./chal8.pl 8.txt
	./chal9.pl
	./chal10.pl 10.txt

4.txt :
	curl -O 'http://cryptopals.com/static/challenge-data/4.txt'
6.txt :
	curl -O 'http://cryptopals.com/static/challenge-data/6.txt'
7.txt :
	curl -O 'http://cryptopals.com/static/challenge-data/7.txt'
8.txt :
	curl -O 'http://cryptopals.com/static/challenge-data/8.txt'
10.txt :
	curl -O 'http://cryptopals.com/static/challenge-data/10.txt'
