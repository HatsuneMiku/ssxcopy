#!/usr/local/bin/python
# -*- coding: utf-8 -*-
'''ssxcopy
ssxcopy.py testsrc testdst
'''

import sys, os, stat
import time

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

def ssxcopy(src, dst):
  for pathname, dirnames, filenames in os.walk(src, topdown=True):
    print 'path: %s' % pathname
    for d in dirnames:
      sd = os.path.join(pathname, d)[len(src) + 1:]
      print 'dir: %s' % sd
    for f in filenames:
      sf = os.path.join(pathname, f)[len(src) + 1:]
      print 'file: %s' % sf

if __name__ == '__main__':
  if(len(sys.argv) < 3):
    print 'Usage: %s src_dir dst_dir' % sys.argv[0]
  else:
    remove_delim = lambda s: s[:-1] if s[-1] == '/' or s[-1] == '\\' else s
    src, dst = map(remove_delim, sys.argv[1:3])
    print 'src: [%s] dst: [%s]' % (src, dst)
    if(not os.path.exists(src)): print 'src path does not exist'
    elif(not os.path.isdir(src)): print 'src path is not a directory'
    elif(not os.path.exists(dst)): print 'dst path does not exist'
    elif(not os.path.isdir(dst)): print 'dst path is not a directory'
    else: ssxcopy(src, dst)
