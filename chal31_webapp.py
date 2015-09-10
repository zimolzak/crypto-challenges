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
        
urls = (
    '/(.*)', 'hello'
)
app = web.application(urls, globals())

class hello:        
    def GET(self, name):
        if not name: 
            name = 'World'
        params = web.input()
        self.hasher = hmac.new(unknown_key, params.file, sha1)
        secret_hash = self.hasher.hexdigest()
        if params.signature == secret_hash:
            return('You are winner, ' + name + '!\n' + params.file
                   + '\n' + params.signature)
        else:
            return('GIT STUFFED!1!' '!\nYou want ' + params.file
                   + ', but your ' + params.signature + ' sux!\nHint: try '
                   + secret_hash)
            #FIXME - Obviously eventually it shouldn't cheat for you.:)

if __name__ == "__main__":
    app.run()
