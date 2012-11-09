#!/usr/local/bin/python
# -*- coding: utf-8 -*-
'''ssxcopy
ssxcopy.py testsrc testdst
'''

import shutil
import sys, os
import time

ENC = 'cp932'
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

def ewrite(s, o=sys.stdout):
  o.write(s.encode(ENC))

def pdotinc(c):
  ewrite('.')
  return c + 1

def plnres(c):
  if c: ewrite('\n')
  return 0

def ssxcopy(src, dst): # must be in unicode
  for pathname, dirnames, filenames in os.walk(src, topdown=True):
    ewrite('path: [%s] scan directories ' % pathname)
    c = 1
    for d in dirnames:
      sd = os.path.join(pathname, d)[len(src) + 1:]
      td = os.path.join(dst, sd)
      if os.path.exists(td): c = pdotinc(c)
      else:
        c = plnres(c)
        ewrite('mkdir: %s\n' % td)
        os.mkdir(td)
    c = plnres(c)
    ewrite('path: [%s] scan files ' % pathname)
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
        ewrite('copy file: %s\n' % tf)
        shutil.copyfile(ff, tf)
        os.utime(tf, (os.stat(ff).st_atime, os.stat(ff).st_mtime))
    c = plnres(c)

if __name__ == '__main__':
  if(len(sys.argv) < 3):
    ewrite('Usage: %s src_dir dst_dir\n' % sys.argv[0], sys.stderr)
  else:
    remove_delim = lambda s: s[:-1] if s[-1] == '/' or s[-1] == '\\' else s
    src, dst = map(remove_delim, map(lambda s: s.decode(ENC), sys.argv[1:3]))
    ewrite('src: [%s] dst: [%s]\n' % (src, dst))
    if(len(src) == 0): ewrite('src may be root', sys.stderr)
    elif(not os.path.exists(src)): ewrite('src does not exist', sys.stderr)
    elif(not os.path.isdir(src)): ewrite('src is not a directory', sys.stderr)
    elif(len(dst) == 0): ewrite('dst may be root', sys.stderr)
    elif(not os.path.exists(dst)): ewrite('dst does not exist', sys.stderr)
    elif(not os.path.isdir(dst)): ewrite('dst is not a directory', sys.stderr)
    else: ssxcopy(src, dst)
