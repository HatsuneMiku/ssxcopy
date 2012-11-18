#!/usr/local/bin/python
# -*- coding: utf-8 -*-
'''uvssccpp
user version secure sync compress crypt pile protocol
'''

import sys, os

BUFSIZ = 40#96

class UVSSCCPP(object):
  def __init__(self, argv):
    self.argv = argv
    self.basedir = os.path.join(os.path.dirname(__file__), 'org')
    self.defopts = [
      ('Help',      self.do_usage,      'Help usage'),
      ('Verbose',   self.do_flag,       'Verbose (must be first)'),
      ('Basedir',   self.do_basedir,    'Basedir (must be last)')]
    self.validopts = ''.join(
      map(lambda o: filter(str.isupper, o[0]), self.defopts)).lower()
    self.longopts = map(lambda o: o[0].lower(), self.defopts)
    self.revopts = {}
    for i in xrange(len(self.defopts)):
      self.revopts['-%s' % self.validopts[i]] = i
      self.revopts['--%s' % self.longopts[i]] = i
    self.opts, self.args, self.procs, self.flags = [], [], [], {}
    try:
      import getopt
      self.opts, self.args = getopt.getopt(self.argv[1:],
        self.validopts, longopts=self.longopts)
      if len(self.args) <= 0:
        self.procs.append((self.do_usage, [None, None]))
      else:
        for opt, arg in self.opts:
          optnum = self.revopts[opt]
          self.procs.append(
            (self.defopts[optnum][1], [self.validopts[optnum], arg]))
    except getopt.GetoptError:
      self.procs.append((self.do_usage, [None, None]))

  def process(self):
    for proc, args in self.procs:
      proc(*args)

  def outerr(self, s):
    print >> sys.stderr, s

  def do_basedir(self, *args):
    self.basedir = self.args[0]

  def do_flag(self, *args):
    self.flags[args[0]] = True

  def do_dummy(self, *args):
    self.outerr('dummy: %s, %s' % (args[0], args[1]))

  def do_usage(self, *args):
    self.outerr('args: %s' % self.args)
    for opt, arg in self.opts:
      self.outerr('opt: %s, arg: %s' % (opt, arg))
    self.outerr('Usage: %s [%s] basedir\n%s' % (
      self.argv[0], self.validopts, '\n'.join([
        ('  %-4s %-16s %s' % (
          '-%s,' % self.validopts[i],
          '--%s:' % self.longopts[i],
          '%s' % self.defopts[i][2])
        ) for i in xrange(len(self.defopts))])))

if __name__ == '__main__':
  UVSSCCPP(sys.argv).process()
