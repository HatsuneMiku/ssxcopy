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
  sys.stdout.write('.')
  return c + 1

def plnres(c):
  if c: sys.stdout.write('\n')
  return 0

def ssxcopy(src, dst):
  for pathname, dirnames, filenames in os.walk(src, topdown=True):
    sys.stdout.write('path: [%s] scan directories ' % pathname)
    c = 1
    for d in dirnames:
      sd = os.path.join(pathname, d)[len(src) + 1:]
      td = os.path.join(dst, sd)
      if os.path.exists(td): c = pdotinc(c)
      else:
        c = plnres(c)
        sys.stdout.write('mkdir: %s\n' % td)
        os.mkdir(td)
    c = plnres(c)
    sys.stdout.write('path: [%s] scan files ' % pathname)
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
        sys.stdout.write('copy file: %s\n' % tf)
        shutil.copyfile(ff, tf)
        os.utime(tf, (os.stat(ff).st_atime, os.stat(ff).st_mtime))
    c = plnres(c)

if __name__ == '__main__':
  if(len(sys.argv) < 3):
    sys.stderr.write('Usage: %s src_dir dst_dir\n' % sys.argv[0])
  else:
    remove_delim = lambda s: s[:-1] if s[-1] == '/' or s[-1] == '\\' else s
    src, dst = map(remove_delim, sys.argv[1:3])
    sys.stdout.write('src: [%s] dst: [%s]\n' % (src, dst))
    if(len(src) == 0): sys.stdout.write('src may be root')
    elif(not os.path.exists(src)): sys.stdout.write('src does not exist')
    elif(not os.path.isdir(src)): sys.stdout.write('src is not a directory')
    elif(len(dst) == 0): sys.stdout.write('dst may be root')
    elif(not os.path.exists(dst)): sys.stdout.write('dst does not exist')
    elif(not os.path.isdir(dst)): sys.stdout.write('dst is not a directory')
    else: ssxcopy(src, dst)
