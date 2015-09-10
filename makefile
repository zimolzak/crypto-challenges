test : 4.txt 6.txt quicktest 20.txt
	./chal4.pl 4.txt > /dev/null  # 30 - 40 sec
	./chal6.pl 6.txt              # 40 sec
	./chal20.py                   # 15-20 sec
	./chal22.py                   # random, 15 - 30 sec
	./chal24.py                   # 15 sec
	./chal31_test.sh              # 7-8 min

quicktest : 7.txt 8.txt 10.txt rand_bytes.txt unknown_key.txt 17.txt 19.txt 25.txt
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
	./chal21.py
	./chal23.py
	./chal25.py
	./chal26.py
	./chal27.py
	./chal28.py
	./chal29.py
	python ./py_md4/test.py
	./chal30.py

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
25.txt : 7.txt
	cp 7.txt 25.txt
#curl -O 'http://cryptopals.com/static/challenge-data/25.txt'
