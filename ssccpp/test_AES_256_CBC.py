#!/usr/local/bin/python
# -*- coding: utf-8 -*-
'''test_AES_256_CBC
'''

import sys, os
import random
import binascii
import hashlib
from Crypto.Cipher import AES

def get_key_iv(passwd, salt):
  h = [''] * 3
  for i in range(len(h)):
    h[i] = hashlib.md5((h[i - 1] if i else '') + passwd + salt).digest()
  return h[0] + h[1], h[2]

def test_AES_256_CBC_encrypt(infile, outfile, passwd, siv=None):
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

def test_AES_256_CBC_decrypt(infile, outfile, passwd, siv=None):
  ifp = open(infile, 'rb')
  ofp = open(outfile, 'wb')
  if siv is None and ifp.read(8) != 'Salted__':
    print 'header Salted__ is not found'
  else:
    if siv is None: # decrypt normal file
      salt = ifp.read(8)
      key, iv = get_key_iv(passwd, salt)
    else: # decrypt private key
      biv = binascii.a2b_hex(siv) # first, convert string to hex (biv 16 bytes)
      salt = biv[:8] # salt is the primary half of biv
      key, iv = get_key_iv(passwd, salt) # create key and iv
      a256c = AES.new(key, AES.MODE_CBC, biv) # * use biv for first 16 bytes *
      ofp.write(a256c.decrypt(ifp.read(16)))
      ifp.seek(0) # * rewind for correct decryption *
    a256c = AES.new(key, AES.MODE_CBC, iv)
    dat = a256c.decrypt(ifp.read())
    if siv is not None: dat = dat[16:] # * skip for rewind length *
    pad = ord(dat[-1])
    if 1 <= pad <= 16: ofp.write(dat[:-pad])
    else:
      ofp.write(dat)
      print 'padding may be incorrect'
  ofp.close()
  ifp.close()

if __name__ == '__main__':
  if len(sys.argv) < 5:
    print 'Usage: %s (encrypt|decrypt) infile outfile passwd [DEK-Info]' % (
      sys.argv[0])
  else:
    if sys.argv[1] == 'encrypt': test_AES_256_CBC_encrypt(*sys.argv[2:])
    elif sys.argv[1] == 'decrypt': test_AES_256_CBC_decrypt(*sys.argv[2:])
    else: print 'please select encrypt or decrypt'
