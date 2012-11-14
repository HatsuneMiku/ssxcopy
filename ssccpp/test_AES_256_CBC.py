#!/usr/local/bin/python
# -*- coding: utf-8 -*-
'''test_AES_256_CBC
'''

import sys, os

def test_AES_256_CBC(infile, outfile, passwd):
  print infile, outfile, passwd
  return

if __name__ == '__main__':
  if len(sys.argv) < 4:
    print 'Usage: %s infile passwd' % sys.argv[0]
  else:
    test_AES_256_CBC(*sys.argv[1:])
