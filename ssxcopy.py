#!/usr/local/bin/python
# -*- coding: utf-8 -*-
'''ssxcopy
ssxcopy.py testsrc testdst
'''

import sys, os, locale
import shutil
import time
import progressbar

ENC = locale.getpreferredencoding()
LINEMAX = 80
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

def ewrite(s, o=sys.stdout):
  o.write(s.encode(ENC))

def pdotinc(c):
  ewrite('.')
  return c + 1 # set flag (need \n)

def plnres(c):
  if c: ewrite('\n')
  return 0 # reset flag (not need \n)

def makeprogress(num):
  if num < LINEMAX: return None
  ewrite('\n')
  widgets = ['(%s): ' % (num), progressbar.Percentage(),
    ' ', progressbar.Bar(marker=progressbar.RotatingMarker()),
    ' ', progressbar.ETA(), ' ', progressbar.FileTransferSpeed()]
  return progressbar.ProgressBar(widgets=widgets, maxval=num).start()

def updateprogress(pgs, count, num):
  pgs.update(count)
  return 0 if count == num else 1 # reset or set flag ((not) need \n)

def ssxcopy(src, dst): # must be in unicode
  for pathname, dirnames, filenames in os.walk(src, topdown=True):
    ewrite('[%s] scan directories ' % pathname)
    num = len(dirnames)
    pgs = makeprogress(num)
    count = 0
    c = 1 # set flag (need \n)
    for d in dirnames:
      count += 1
      sd = os.path.join(pathname, d)[len(src) + 1:]
      td = os.path.join(dst, sd)
      if os.path.exists(td):
        c = updateprogress(pgs, count, num) if pgs else pdotinc(c)
      else:
        c = plnres(c)
        ewrite('mkdir: %s\n' % td)
        os.mkdir(td)
    c = plnres(c)
    if pgs: pgs.finish()
    ewrite('[%s] scan files ' % pathname)
    num = len(filenames)
    pgs = makeprogress(num)
    count = 0
    c = 1 # set flag (need \n)
    for f in filenames:
      count += 1
      ff = os.path.join(pathname, f)
      sf = ff[len(src) + 1:]
      tf = os.path.join(dst, sf)
      if os.path.exists(tf) \
      and long(os.stat(ff).st_mtime) <= long(os.stat(tf).st_mtime):
        c = updateprogress(pgs, count, num) if pgs else pdotinc(c)
      else:
        c = plnres(c)
        ewrite('copy file: %s\n' % tf)
        shutil.copyfile(ff, tf)
        os.utime(tf, (os.stat(ff).st_atime, os.stat(ff).st_mtime))
    c = plnres(c)
    if pgs: pgs.finish()

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
