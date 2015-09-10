#!/usr/bin/env python

#     chal31_webapp.py - Rudimentary web.py app, so that server
#     verifies that signature param is valid for file param. 40 hex
#     chars is what you should try to guess.
#
#     http://0.0.0.0:8080/test?file=foo&signature=
#     12471c4ce67d411fff413a6b773cb3f0b091d765
# 
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

import web
import hmac
from hashlib import sha1
from cryptopals import unknown_key
import time
        
urls = (
    '/(.*)', 'hello'
)
app = web.application(urls, globals())

def insecure_compare(a,b):
    assert type(a) == type(str()) or type(a) == type(unicode())
    assert type(b) == type(str()) or type(b) == type(unicode())
    i = -1
    while(1):
        i += 1
        try:
            still_equal = (a[i] == b[i])
            time.sleep(0.050)
        except IndexError:
            if len(a) == len(b):
                return True
            else:
                return False
        if not still_equal:
            return False

def internalerror():
    return web.internalerror("Bad, bad server. No donut for you.")

app.internalerror = internalerror

class hello:        
    def GET(self, name):
        print app #deleteme
        #app.internalerror() #deleteme
        raise web.internalerror()
        if not name: 
            name = 'World'
        params = web.input()
        if 'file' in params.keys() and 'signature' in params.keys():
            self.hasher = hmac.new(unknown_key, params.file, sha1)
            secret_hash = str(self.hasher.hexdigest())
            if insecure_compare(params.signature, secret_hash):
                return('You are winner, ' + name + '!\n' + params.file
                       + '\n' + params.signature)
            else:
                #app.internalerror()
                return('GIT STUFFED!1!' '!\nYou want ' + params.file
                       + ', but your ' + params.signature + ' sux!\nHint: try '
                       + secret_hash)
            #FIXME - Obviously eventually it shouldn't cheat for you.:)
        else:
            return 'Hello, ' + name + '!'

if __name__ == "__main__":
    app.run()
