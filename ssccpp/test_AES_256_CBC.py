#!/usr/local/bin/python
# -*- coding: utf-8 -*-
'''test_AES_256_CBC
http://en.wikipedia.org/wiki/Cipher_block_chaining
  #Cipher-block_chaining_.28CBC.29

# in source
openssl/crypto/pem/pem_lib.c
# encrypt private key
int PEM_ASN1_write_bio(int (*i2d)(), const char *name, BIO *bp, char *x,
  const EVP_CIPHER *enc, unsigned char *kstr, int klen,
  pem_password_cb *callback, void *u)
# decrypt private key
int PEM_do_header(EVP_CIPHER_INFO *cipher, unsigned char *data, long *plen,
  pem_password_cb *callback,void *u)
# following code is for AES-256-CBC only
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
  if siv is None: # encrypt normal file
    ofp.write('Salted__')
    salt = ''.join(chr(random.randint(0, 0xFF)) for _ in range(8))
    ofp.write(salt)
    key, iv = get_key_iv(passwd, salt)
  else: # encrypt private key
    biv = binascii.a2b_hex(siv) # first, convert string to hex (biv 16 bytes)
    salt = biv[:8] # salt is the primary half of biv
    key, iv = get_key_iv(passwd, salt) # create key and iv
    iv = biv # reset iv to original biv
  print 'salt=%s' % binascii.b2a_hex(salt)
  print 'key=%s' % binascii.b2a_hex(key)
  print 'iv =%s' % binascii.b2a_hex(iv)
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
      iv = biv # reset iv to original biv
    print 'salt=%s' % binascii.b2a_hex(salt)
    print 'key=%s' % binascii.b2a_hex(key)
    print 'iv =%s' % binascii.b2a_hex(iv)
    a256c = AES.new(key, AES.MODE_CBC, iv)
    dat = a256c.decrypt(ifp.read())
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
