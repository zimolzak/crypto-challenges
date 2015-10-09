#!/usr/bin/env python

#     chal46.py - RSA parity oracle
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from cryptopals import warn
import rsa
import random
import base64
from math import log

print "Generating keypair..."
#pubkey, privkey = rsa.keypair(1024)
# Just faster, less annoying to spec a global for now....

pubkey = [3, 25372685545756587867312067264457344491945461146619641801774325727363748642449611047944537097108904190995065240467573171031547338967808748530782980102928430686220986922869097419970839834765967162877500458206107182850822617078389983268329556421559714075213037413753239601770327886473947665405034587451621055919061690179422018670751126556207771961237246109183142391661314413251953513912784656206550419852565110919309882093400660645685506390448733941354454124718721560972593782095336640144942958047768295693770668226044393783914138228006213953792121725494173906444760796547999555756517357856173401557274915822299856969333L]

privkey = [16915123697171058578208044842971562994630307431079761201182883818242499094966407365296358064739269460663376826978382114021031559311872499020521986735285620457480657948579398279980559889843978108585000305470738121900548411385593322178886370947706476050142024942502159734513551924315965110270023058301080703945827927585547548661266312433506621573531538476994299021233397375073279066863381645998826311941843896675214029978168683708234984715331150895801763553677450448478704495626356444984550397480191707147365648241357449406862538452105179557110804239811897740935501915600530584297271564572030119986793990795715516392179L, 25372685545756587867312067264457344491945461146619641801774325727363748642449611047944537097108904190995065240467573171031547338967808748530782980102928430686220986922869097419970839834765967162877500458206107182850822617078389983268329556421559714075213037413753239601770327886473947665405034587451621055919061690179422018670751126556207771961237246109183142391661314413251953513912784656206550419852565110919309882093400660645685506390448733941354454124718721560972593782095336640144942958047768295693770668226044393783914138228006213953792121725494173906444760796547999555756517357856173401557274915822299856969333L]

print "Done!"

e = pubkey[0]
n = pubkey[1]

def parity(ciphertext):
    """Ciphertext is an integer."""
    decrypt_int = rsa.crypt(ciphertext, privkey)
    return int(decrypt_int % 2) # int, not a long.

def multiply(ciphertext, k, e, n):
    return (ciphertext * k ** e) % n

def cleanup(string, substitution=''):
    safe = ''
    for c in string:
        if 32 <= ord(c) <= 126:
            safe += c
        else:
            safe += substitution
    return safe

b64s = 'VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=='
plaintext = base64.b64decode(b64s)
ciphertext = rsa.encrypt_string(plaintext, pubkey)
# um, if e=3, I don't think this string wraps the modulus. So in
# theory, I think we could just cube-root it, but oh well.

#### test
hi = 'Hi'
c_hi = rsa.encrypt_string(hi, pubkey)
D = multiply(c_hi, 2, pubkey[0], pubkey[1])
assert rsa.s2i(hi) * 2 == rsa.crypt(D, privkey)
print "ok"
####

M = 2
bounds = [0, n]
half = rsa.invmod(2, n)
for i in range(2048):
    p = parity(multiply(ciphertext, 2, e, n)) # fixme - replace 2.
    half_the_dist = (bounds[1] - bounds[0]) / 2
    if p == 0:
        bounds = [bounds[0], bounds[1] -  half_the_dist]
        M = (M + rsa.invmod(2**i, n)) % n
    elif p == 1:
        bounds = [bounds[0] + half_the_dist, bounds[1]]
        M = (M - rsa.invmod(2**i, n)) % n
    ciphertext = ciphertext >> 1
    if i % 8 == 7:
        # print log(half_the_dist, 2)
        print cleanup(rsa.i2s(bounds[1]), '_') # get 256 char wide screen
        print M

#### tests ####

warn("Passed assertions:", __file__)
