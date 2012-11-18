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
  IV_LENGTH = 16
  DEFAULT_CHUNKSIZE = 16 * 4096
  DEFAULT_PROGRESS_MAX = 1000000

  @staticmethod
  def getiv(length=IV_LENGTH):
    return ''.join(chr(random.randint(0, 0xFF)) for _ in range(length))

  def __init__(self, key, chunksize=DEFAULT_CHUNKSIZE):
    self.key = key
    self.key32 = hashlib.sha256(key)
    self.chunksize = chunksize

  def progress(self, mode, name, maxval=DEFAULT_PROGRESS_MAX):
    sname = '%s...%s' % (name[:9], name[-9:]) if len(name) >= 21 else name
    self.widgets = ['%s %s: ' % (mode, sname),
      pgbar.Bar(marker=pgbar.RotatingMarker()), ' ', pgbar.Percentage(),
      ' ', pgbar.ETA(), ' ', pgbar.FileTransferSpeed()]
    return pgbar.ProgressBar(widgets=self.widgets, maxval=maxval).start()

  def file_encrypt(self, infile, outfile=None):
    plainmd5, encryptmd5 = hashlib.md5(), hashlib.md5()
    if not outfile: outfile = infile + '.enc'
    filesize = os.path.getsize(infile)
    iv = AES256CBC.getiv()
    self.pbar = self.progress('e', infile)
    encryptor = AES.new(self.key32.digest(), AES.MODE_CBC, iv)
    ifp = open(infile, 'rb')
    ofp = open(outfile, 'wb')
    ofp.write(struct.pack('>Q', filesize))
    ofp.write(iv)
    c = 0
    while True:
      chunk = ifp.read(self.chunksize)
      if len(chunk) == 0: break
      elif len(chunk) % 16 != 0: chunk += ' ' * (16 - len(chunk) % 16)
      ofp.write(encryptor.encrypt(chunk))
      c += len(chunk)
      self.pbar.update(c * AES256CBC.DEFAULT_PROGRESS_MAX / filesize)
    ofp.close()
    ifp.close()
    self.pbar.finish()
    return (plainmd5, encryptmd5)

  def file_decrypt(self, infile, outfile=None):
    plainmd5, decryptmd5 = hashlib.md5(), hashlib.md5()
    if not outfile: outfile = os.path.splitext(infile)[0]
    ifp = open(infile, 'rb')
    orgsize = struct.unpack('>Q', ifp.read(struct.calcsize('Q')))[0]
    iv = ifp.read(AES256CBC.IV_LENGTH)
    self.pbar = self.progress('d', infile)
    decryptor = AES.new(self.key32.digest(), AES.MODE_CBC, iv)
    ofp = open(outfile, 'wb')
    c = 0
    while True:
      chunk = ifp.read(self.chunksize)
      if len(chunk) == 0: break
      ofp.write(decryptor.decrypt(chunk))
      c += len(chunk)
      self.pbar.update(c * AES256CBC.DEFAULT_PROGRESS_MAX / orgsize)
    ofp.truncate(orgsize)
    ofp.close()
    ifp.close()
    self.pbar.finish()
    return (plainmd5, decryptmd5)

  def file_compress(self, infile, outfile=None):
    plainmd5, compressmd5 = hashlib.md5(), hashlib.md5()
    if not outfile: outfile = infile + '.bz2'
    filesize = os.path.getsize(infile)
    self.pbar = self.progress('c', infile)
    compressor = bz2.BZ2Compressor(9)
    ifp = open(infile, 'rb')
    ofp = open(outfile, 'wb')
    c = 0
    while True:
      chunk = ifp.read(self.chunksize)
      if len(chunk) == 0: break
      ofp.write(compressor.compress(chunk))
      c += len(chunk)
      self.pbar.update(c * AES256CBC.DEFAULT_PROGRESS_MAX / filesize)
    ofp.write(compressor.flush())
    ofp.close()
    ifp.close()
    self.pbar.finish()
    return (plainmd5, compressmd5)

  def file_decompress(self, infile, outfile=None):
    plainmd5, decompressmd5 = hashlib.md5(), hashlib.md5()
    if not outfile: outfile = os.path.splitext(infile)[0]
    filesize = os.path.getsize(infile)
    self.pbar = self.progress('x', infile)
    decompressor = bz2.BZ2Decompressor()
    ifp = open(infile, 'rb')
    ofp = open(outfile, 'wb')
    c = 0
    while True:
      chunk = ifp.read(self.chunksize)
      if len(chunk) == 0: break
      ofp.write(decompressor.decompress(chunk))
      c += len(chunk)
      self.pbar.update(c * AES256CBC.DEFAULT_PROGRESS_MAX / filesize)
    ofp.close()
    ifp.close()
    self.pbar.finish()
    return (plainmd5, decompressmd5)

  def gets(self):
    return sys.stdin.readline().rstrip()

  def stream_compress_encrypt(self):
    plainmd5, c_md5, e_md5 = hashlib.md5(), hashlib.md5(), hashlib.md5()
    self.pbar = self.progress('c', infile)
    self.pbar.finish()
    return (plainmd5, c_md5, e_md5)

  def stream_decrypt_decompress(self):
    plainmd5, d_md5, x_md5 = hashlib.md5(), hashlib.md5(), hashlib.md5()
    self.pbar = self.progress('x', infile)
    self.pbar.finish()
    return (plainmd5, d_md5, x_md5)

if __name__ == '__main__':
  iv = AES256CBC.getiv()
  key32 = hashlib.sha256('password')
  print key32.hexdigest()
  plaintext = 'c' * 16 + 'a' * 512 + 'b' * 1024 * 1024
  print len(plaintext) - 16 - 512            # 1048576
  encryptor = AES.new(key32.digest(), AES.MODE_CBC, iv)
  ciphertext = encryptor.encrypt(plaintext)
  print len(ciphertext) - 16 - 512      # 1048576
  decryptor = AES.new(key32.digest(), AES.MODE_CBC, iv)
  txt = decryptor.decrypt(ciphertext)
  print len(txt) - 16 - 512             # 1048576
  print 'compare: %s' % (txt == plaintext)

  plainfile = './test.mp3' # './aes256cbc.py'
  a256c = AES256CBC('key')

  cipherfile = '%s_test1.enc' % plainfile
  a256c.file_encrypt(plainfile)
  if os.path.exists(cipherfile): os.remove(cipherfile)
  os.rename('%s.enc' % plainfile, cipherfile)
  a256c.file_decrypt(cipherfile)

  compressedfile = '%s_test2.bz2' % plainfile
  a256c.file_compress(plainfile)
  if os.path.exists(compressedfile): os.remove(compressedfile)
  os.rename('%s.bz2' % plainfile, compressedfile)
  a256c.file_decompress(compressedfile)
