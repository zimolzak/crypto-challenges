#!/bin/sh

./chal31_webapp.py &
pid=$!
sleep 2
./chal31.py
kill $pid
