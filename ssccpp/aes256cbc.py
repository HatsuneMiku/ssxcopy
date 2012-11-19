#!/usr/local/bin/python
# -*- coding: utf-8 -*-
'''aes256cbc
reference ( progressbar\compress_decompress.txt )
'''

import sys, os
import time
import progressbar as pgbar
import struct
import random
import hashlib
from Crypto.Cipher import AES
import bz2

class AES256CBC(object):
  LENGTH_SALT = 8
  DEFAULT_CHUNKSIZE = 16 * 4096

  @staticmethod
  def get_random_bytes(length=LENGTH_SALT):
    return ''.join(chr(random.randint(0, 0xFF)) for _ in range(length))

  @staticmethod
  def get_key_iv(passwd, salt):
    h = [''] * 3
    for i in range(len(h)):
      h[i] = hashlib.md5((h[i - 1] if i else '') + passwd + salt).digest()
    return h[0] + h[1], h[2]

  def __init__(self, passwd, chunksize=DEFAULT_CHUNKSIZE):
    self.passwd = passwd
    self.chunksize = chunksize

  def progress(self, mode, name, maxval):
    sname = '%s...%s' % (name[:9], name[-9:]) if len(name) >= 21 else name
    self.widgets = ['%s %s: ' % (mode, sname),
      pgbar.Bar(marker=pgbar.RotatingMarker()), ' ', pgbar.Percentage(),
      ' ', pgbar.ETA(), ' ', pgbar.FileTransferSpeed()]
    return pgbar.ProgressBar(widgets=self.widgets, maxval=maxval).start()

  def file_encrypt(self, infile, outfile=None):
    plainmd5, encryptmd5 = hashlib.md5(), hashlib.md5()
    if outfile is None: outfile = infile + '.enc'
    filesize = os.path.getsize(infile)
    self.pbar = self.progress('e', infile, filesize)
    ifp = open(infile, 'rb')
    ofp = open(outfile, 'wb')
    ofp.write('Salted__')
    salt = AES256CBC.get_random_bytes()
    ofp.write(salt)
    key32, iv16 = AES256CBC.get_key_iv(self.passwd, salt)
    encryptor = AES.new(key32, AES.MODE_CBC, iv16)
    c, d = 0, False
    while True:
      chunk = ifp.read(self.chunksize)
      if len(chunk) == 0 or len(chunk) % 16 != 0:
        d = True
        pad = 16 - (len(chunk) % 16) # pad should be never 0,
        chunk += chr(pad) * pad # so remove them later 1-16
      ofp.write(encryptor.encrypt(chunk))
      c += len(chunk)
      self.pbar.update(c if c <= filesize else filesize)
      if d: break
    ofp.close()
    ifp.close()
    self.pbar.finish()
    return (plainmd5, encryptmd5)

  def file_decrypt(self, infile, outfile=None):
    plainmd5, decryptmd5 = hashlib.md5(), hashlib.md5()
    if outfile is None: outfile = os.path.splitext(infile)[0]
    filesize = os.path.getsize(infile)
    self.pbar = self.progress('d', infile, filesize)
    ifp = open(infile, 'rb')
    if ifp.read(AES256CBC.LENGTH_SALT) != 'Salted__':
      sys.stderr.write('header Salted__ is not found\n')
    else:
      salt = ifp.read(AES256CBC.LENGTH_SALT)
      key32, iv16 = AES256CBC.get_key_iv(self.passwd, salt)
      decryptor = AES.new(key32, AES.MODE_CBC, iv16)
      ofp = open(outfile, 'wb')
      c, d = AES256CBC.LENGTH_SALT * 2, False
      while True:
        chunk = ifp.read(self.chunksize)
        if len(chunk) == 0:
          sys.stderr.write('unexpected EOF is found (%d)\n' % (c))
          break
        dat = decryptor.decrypt(chunk)
        c += len(chunk)
        if c >= filesize:
          d = True
          pad = ord(dat[-1])
          if 1 <= pad <= 16: ofp.write(dat[:-pad])
          else:
            sys.stderr.write('padding may be incorrect\n')
            ofp.write(dat)
        else:
          ofp.write(dat)
        self.pbar.update(c if c <= filesize else filesize)
        if d: break
      ofp.close()
    ifp.close()
    self.pbar.finish()
    return (plainmd5, decryptmd5)

  def file_compress(self, infile, outfile=None):
    plainmd5, compressmd5 = hashlib.md5(), hashlib.md5()
    if outfile is None: outfile = infile + '.bz2'
    filesize = os.path.getsize(infile)
    self.pbar = self.progress('c', infile, filesize)
    compressor = bz2.BZ2Compressor(9)
    ifp = open(infile, 'rb')
    ofp = open(outfile, 'wb')
    c = 0
    while True:
      chunk = ifp.read(self.chunksize)
      if len(chunk) == 0: break
      ofp.write(compressor.compress(chunk))
      c += len(chunk)
      self.pbar.update(c)
    ofp.write(compressor.flush())
    ofp.close()
    ifp.close()
    self.pbar.finish()
    return (plainmd5, compressmd5)

  def file_decompress(self, infile, outfile=None):
    plainmd5, decompressmd5 = hashlib.md5(), hashlib.md5()
    if outfile is None: outfile = os.path.splitext(infile)[0]
    filesize = os.path.getsize(infile)
    self.pbar = self.progress('x', infile, filesize)
    decompressor = bz2.BZ2Decompressor()
    ifp = open(infile, 'rb')
    ofp = open(outfile, 'wb')
    c = 0
    while True:
      chunk = ifp.read(self.chunksize)
      if len(chunk) == 0: break
      ofp.write(decompressor.decompress(chunk))
      c += len(chunk)
      self.pbar.update(c)
    ofp.close()
    ifp.close()
    self.pbar.finish()
    return (plainmd5, decompressmd5)

  def gets(self):
    return sys.stdin.readline().rstrip()

  def stream_compress_encrypt(self):
    plainmd5, c_md5, e_md5 = hashlib.md5(), hashlib.md5(), hashlib.md5()
    filesize = os.path.getsize(infile)
    self.pbar = self.progress('c', infile, filesize)
    self.pbar.finish()
    return (plainmd5, c_md5, e_md5)

  def stream_decrypt_decompress(self):
    plainmd5, d_md5, x_md5 = hashlib.md5(), hashlib.md5(), hashlib.md5()
    filesize = os.path.getsize(infile)
    self.pbar = self.progress('x', infile, filesize)
    self.pbar.finish()
    return (plainmd5, d_md5, x_md5)

if __name__ == '__main__':
  salt = AES256CBC.get_random_bytes()
  key32, iv16 = AES256CBC.get_key_iv('password', salt)
  plaintext = 'c' * 16 + 'a' * 512 + 'b' * 1024 * 1024
  print len(plaintext) - 16 - 512       # 1048576
  encryptor = AES.new(key32, AES.MODE_CBC, iv16)
  ciphertext = encryptor.encrypt(plaintext)
  print len(ciphertext) - 16 - 512      # 1048576
  decryptor = AES.new(key32, AES.MODE_CBC, iv16)
  txt = decryptor.decrypt(ciphertext)
  print len(txt) - 16 - 512             # 1048576
  print 'compare: %s' % (txt == plaintext)

  # plainfile = './aes256cbc.py'
  plainfile = './privatedata/test.mp3' # 60228786 = (14704:1202), 1202 = (75:2)
  a256c = AES256CBC('key')

  a256c.file_encrypt(plainfile)
  cipherfile = '%s_test1.enc' % plainfile
  if os.path.exists(cipherfile): os.remove(cipherfile)
  os.rename('%s.enc' % plainfile, cipherfile)
  a256c.file_decrypt(cipherfile)

  a256c.file_compress(plainfile)
  compressedfile = '%s_test2.bz2' % plainfile
  if os.path.exists(compressedfile): os.remove(compressedfile)
  os.rename('%s.bz2' % plainfile, compressedfile)
  a256c.file_decompress(compressedfile)
