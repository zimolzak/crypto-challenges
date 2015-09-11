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

delay = 0.0035   #### A VERY IMPORTANT NUMBER!

def insecure_compare(a,b):
    assert type(a) == type(str()) or type(a) == type(unicode())
    assert type(b) == type(str()) or type(b) == type(unicode())
    i = -1
    while(1):
        i += 1
        try:
            still_equal = (a[i] == b[i])
            time.sleep(delay)
        except IndexError:
            if len(a) == len(b):
                return True
            else:
                return False
        if not still_equal:
            return False

def internalerror():
    params = web.input()
    filename = str(params.file)
    sig = str(params.signature)
    hasher = hmac.new(unknown_key, params.file, sha1)
    hint = str(hasher.hexdigest())
    return web.internalerror('<pre>GIT STUFFED!1!!\nYou want ' + filename
                             + ', but your ' + sig + ' sux!\nHint: try '
                             + hint + '</pre>')

app.internalerror = internalerror

class hello:        
    def GET(self, name):
        if not name: 
            name = 'World'
        params = web.input()
        if 'file' in params.keys() and 'signature' in params.keys():
            self.hasher = hmac.new(unknown_key, params.file, sha1)
            secret_hash = str(self.hasher.hexdigest())
            if insecure_compare(params.signature, secret_hash):
                return('You are winner, ' + name
                       + '!\nYou get the file called: ' + params.file
                       + '\nBecause of your excellent ' + params.signature)
            else:
                raise web.internalerror()
        else:
            return 'Hello, ' + name + '!'

if __name__ == "__main__":
    print "Delay is", delay*1000, "ms."
    app.run()
