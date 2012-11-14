#!/usr/local/bin/python
# -*- coding: utf-8 -*-
'''test_AES_256_CBC
'''

import sys, os
import random
import hashlib
from Crypto.Cipher import AES

def get_key_iv(passwd, salt):
  h0 = hashlib.md5(passwd + salt).digest()
  h1 = hashlib.md5(h0 + passwd + salt).digest()
  h2 = hashlib.md5(h1 + passwd + salt).digest()
  return h0 + h1, h2

def test_AES_256_CBC_encrypt(infile, outfile, passwd):
  ifp = open(infile, 'rb')
  ofp = open(outfile, 'wb')
  ofp.write('Salted__')
  salt = ''.join(chr(random.randint(0, 0xFF)) for _ in range(8))
  ofp.write(salt)
  key, iv = get_key_iv(passwd, salt)
  a256c = AES.new(key, AES.MODE_CBC, iv)
  dat = ifp.read()
  pad = 16 - (len(dat) % 16) # pad should be never 0, so remove them later 1-16
  ofp.write(a256c.encrypt(dat + (chr(pad) * pad)))
  ofp.close()
  ifp.close()

def test_AES_256_CBC_decrypt(infile, outfile, passwd):
  ifp = open(infile, 'rb')
  ofp = open(outfile, 'wb')
  if ifp.read(8) != 'Salted__': print 'header Salted__ is not found'
  else:
    salt = ifp.read(8)
    key, iv = get_key_iv(passwd, salt)
    a256c = AES.new(key, AES.MODE_CBC, iv)
    dat = a256c.decrypt(ifp.read())
    ofp.write(dat[:-ord(dat[-1])])
  ofp.close()
  ifp.close()

if __name__ == '__main__':
  if len(sys.argv) < 5:
    print 'Usage: %s (encrypt|decrypt) infile passwd' % sys.argv[0]
  else:
    if sys.argv[1] == 'encrypt': test_AES_256_CBC_encrypt(*sys.argv[2:])
    elif sys.argv[1] == 'decrypt': test_AES_256_CBC_decrypt(*sys.argv[2:])
    else: print 'please select encrypt or decrypt'
