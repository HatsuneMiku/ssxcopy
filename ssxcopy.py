#!/usr/local/bin/python
# -*- coding: utf-8 -*-
'''ssxcopy
ssxcopy.py testsrc testdst
'''

import shutil
import sys, os
import time

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

def pdotinc(c):
  print '.',
  return c + 1

def plnres(c):
  if c: print
  return 0

def ssxcopy(src, dst):
  for pathname, dirnames, filenames in os.walk(src, topdown=True):
    print 'path: [%s] scan directories' % pathname,
    c = 1
    for d in dirnames:
      sd = os.path.join(pathname, d)[len(src) + 1:]
      td = os.path.join(dst, sd)
      if os.path.exists(td): c = pdotinc(c)
      else:
        c = plnres(c)
        print 'mkdir: %s' % td
        os.mkdir(td)
    c = plnres(c)
    print 'path: [%s] scan files' % pathname,
    c = 1
    for f in filenames:
      ff = os.path.join(pathname, f)
      sf = ff[len(src) + 1:]
      tf = os.path.join(dst, sf)
      if os.path.exists(tf) \
      and long(os.stat(ff).st_mtime) <= long(os.stat(tf).st_mtime):
        c = pdotinc(c)
      else:
        c = plnres(c)
        print 'copy file: %s' % tf
        shutil.copyfile(ff, tf)
        os.utime(tf, (os.stat(ff).st_atime, os.stat(ff).st_mtime))
    c = plnres(c)

if __name__ == '__main__':
  if(len(sys.argv) < 3):
    print 'Usage: %s src_dir dst_dir' % sys.argv[0]
  else:
    remove_delim = lambda s: s[:-1] if s[-1] == '/' or s[-1] == '\\' else s
    src, dst = map(remove_delim, sys.argv[1:3])
    print 'src: [%s] dst: [%s]' % (src, dst)
    if(len(src) == 0): print 'src path may be root'
    elif(not os.path.exists(src)): print 'src path does not exist'
    elif(not os.path.isdir(src)): print 'src path is not a directory'
    elif(len(dst) == 0): print 'dst path may be root'
    elif(not os.path.exists(dst)): print 'dst path does not exist'
    elif(not os.path.isdir(dst)): print 'dst path is not a directory'
    else: ssxcopy(src, dst)
