test : 4.txt 6.txt quicktest
	./chal4.pl 4.txt > /dev/null
	./chal6.pl 6.txt

quicktest : 7.txt 8.txt 10.txt rand_bytes.txt unknown_key.txt 17.txt 19.txt 20.txt
	./chal1.pl
	./chal2.pl
	./chal3.pl
	./chal5.pl
	./chal7.pl 7.txt
	./chal8.pl 8.txt
	./chal9.pl
	./chal10.pl 10.txt
	./chal11.pl
	./chal12.pl
	./chal13.pl
	./chal14.pl
	./chal15.pl
	./chal16.pl
	./chal17.py
	./chal18.py
	./chal19.py
	./chal20.py  # takes 15-20 sec
	./chal21.py
	./chal23.py
	./chal24.py
	./chal22.py  # takes random amount of time, 15 - 30 sec

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
rand_bytes.txt :
	./rand_count_rand_bytes.pl > rand_bytes.txt
20.txt :
	curl -O 'http://cryptopals.com/static/challenge-data/20.txt'
