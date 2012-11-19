#!/usr/local/bin/python
# -*- coding: utf-8 -*-
'''ssccpp
secure sync compress crypt pile protocol
../network/node_leaf.txt
../privatedata/private_memo.txt
'''

import sys, os
import md5
import subprocess
import datetime
import kinterbasdb

BUFSIZ = 40#96

DBPATH = 'privatedata'
DBNAME = os.path.join(os.path.dirname(__file__), DBPATH, 'fbssccpp.fdb')
DBUSER = '********' # from config
DBPASS = '********' # from config
DBCHAR = 'UTF8'

if not kinterbasdb.initialized:
  kinterbasdb.init(type_conv=200, concurrency_level=1)

"""
cn = kinterbasdb.create_database('''
create database '%s' page_size 16384
  user '%s' password '%s' default character set %s;
''' % (
  DBNAME, DBUSER, DBPASS, DBCHAR))
cn.close()
# create table / unique index / sequence / trigger ...
"""

class SSCCPP(object):
  def __init__(self, argv):
    self.argv = argv
    self.basedir = os.path.join(os.path.dirname(__file__), 'data')
    self.defopts = [
      ('Help',      self.do_usage,      'Help usage'),
      ('Verbose',   self.do_flag,       'Verbose (must be first)'),
      ('Test',      self.do_test,       'Test'),
      ('Sjis',      self.do_flag,       'Sjis source'),
      ('Utf8',      self.do_flag,       'Utf8 source (default)'),
      ('Query',     self.do_query,      'Query'),
      ('Dir',       self.do_flag,       'Dir (must be first)'),
      ('File',      self.do_flag,       'File (must be first)'),
      ('mAkedir',   self.do_makedir,    'mAkedir'),
      ('Compress',  self.do_compress,   'Compress file'),
      ('eXtract',   self.do_extract,    'eXtract file'),
      ('Move',      self.do_move,       'Move dir/file'),
      ('Erase',     self.do_erase,      'Erase dir/file'),
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

  def gets(self):
    return sys.stdin.readline().rstrip()

  def sqlconnect(self):
    self.cn = kinterbasdb.connect(dsn=DBNAME,
      user=DBUSER, password=DBPASS, charset=DBCHAR)
    self.cur = self.cn.cursor()

  def sqlexec(self, sql, locktable=None):
    if locktable:
      '''
set transaction read write isolation level read committed no record_version
 wait lock timeout 30 reserving
  TABLENAME for protected read, TABLENAME for protected write;
      '''
      tpb = kinterbasdb.TPB() # kinterbasdb.isc_tpb_version3
      tpb.access_mode = kinterbasdb.isc_tpb_write # read or write
      tpb.isolation_level = kinterbasdb.isc_tpb_read_committed \
        # + kinterbasdb.isc_tpb_no_rec_version # default ?
      tpb.lock_resolution = kinterbasdb.isc_tpb_wait
      tpb.lock_timeout = 30
      tpb.table_reservation[locktable] = (
        kinterbasdb.isc_tpb_protected, kinterbasdb.isc_tpb_lock_write) # read
      self.cn.begin(tpb=tpb.render())
    for s in sql.split(';'):
      e = s.strip()
      if e != '':
        e = '%s;' % e
        self.outerr(e)
        self.cur.execute(e)
    self.cn.commit()

  def sqlquery(self, sql):
    self.cur.execute(sql)
    return self.cur.fetchall()

  def sqlclose(self):
    self.cur.close()
    self.cn.close()

  def do_query(self, *args):
    found = False
    pname = self.gets()
    sname = self.gets()
    if self.flags.get('d', None):
      self.sqlconnect()
      sql = '''select * from tnode where lname = '%s/%s';''' % (pname, sname)
      for row in self.sqlquery(sql):
        print 'ok'
        print row['dname']
        print row['lname']
        print row['sname']
        print row['tsc']
        print row['tse']
        print row['sizep']
        print row['md5p']
        found = True
        break
      self.sqlclose()
    elif self.flags.get('f', None):
      self.sqlconnect()
      sql = '''select * from tnode where lname = '%s';''' % (pname)
      for drow in self.sqlquery(sql):
        sql = '''select * from tleaf where pnode = %s and sname = '%s';''' % (
          drow['id'], sname)
        for row in self.sqlquery(sql):
          print 'ok'
          print drow['dname']
          print drow['lname']
          print row['sname']
          print row['tsc']
          print row['tse']
          print row['sizep']
          print row['md5p']
          found = True
          break
        if found: break
      self.sqlclose()
    else:
      self.outerr('use option d/f before command')
    if not found: print 'not found'

  def do_makedir(self, *args):
    found = False
    pname = self.gets()
    sname = self.gets()
    #
    # must be in transaction
    #
    self.sqlconnect()
    sql = '''select id from tnode where lname = '%s/%s';''' % (pname, sname)
    for row in self.sqlquery(sql):
      found = True
      break
    self.sqlclose()
    if found:
      print 'already exists'
      return
    pnode = 0
    dname = ''
    if pname != '':
      self.sqlconnect()
      sql = '''select id, dname from tnode where lname = '%s';''' % (pname)
      for row in self.sqlquery(sql):
        pnode = row['id']
        dname = row['dname']
        break
      self.sqlclose()
      if pnode == 0:
        print 'parent directory [%s] is not found' % (pname)
        return
    newid = 0
    self.sqlconnect()
    sql = '''insert into tnode (pnode, sname, dname, lname) values (
%s, '%s', '%s', '%s');''' % (
      pnode, sname, '%s/%s' % (dname, pnode), '%s/%s' % (pname, sname))
    self.sqlexec(sql, locktable='tnode')
    sql = '''select * from tnode where dname = '%s/%s';''' % (dname, pnode)
    for row in self.sqlquery(sql):
      newid = row['id']
      break
    self.sqlclose()
    if newid == 0:
      print 'cannot get newid for [%s/%s]' % (dname, pnode)
      return
    # mkdir self.basedir / dname / pnode / newid
    print 'ok'

  def do_compress(self, *args):
    pname = self.gets()
    sname = self.gets()
    tsc = self.gets()
    tse = self.gets()
    sizep = self.gets()
    dum = self.gets()
    if not sizep.isdigit():
      self.outerr('illeagal size')
      return
    siz = int(sizep)
    cnt = 0
    md5p_calc = md5.md5()
    data = ''
    while True:
      tmp = sys.stdin.read((siz - cnt) if siz - cnt < BUFSIZ else BUFSIZ)
      md5p_calc.update(tmp)
      data += tmp
      cnt += len(tmp)
      if cnt >= siz: break
    dum = self.gets()
    md5p = self.gets()

    if md5p != md5p_calc.hexdigest():
      self.outerr('md5p is not correct')
      self.outerr('%s %s' % (pname, sname))
      self.outerr('%s %s %s' % (tsc, tse, sizep))
      self.outerr('%s %s' % (md5p, md5p_calc.hexdigest()))
      return
    print 'ok'

  def do_extract(self, *args):
    print 'ok'

  def do_move(self, *args):
    print 'ok'

  def do_erase(self, *args):
    print 'ok'

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

  def do_test(self, *args):
    self.sqlconnect()
    sql = '''
update ttest set c1 = c1 + 1;
insert into ttest (c1, c2, c3, c4, c5, c6) values (
1, 'abc', 'DEF %s', 'test', 'ABABAB', '2011-06-24 09:28:12.345');
delete from ttest
 where id < (select gen_id(gen_ttest_id, 0) from rdb$database) - 2;
''' % (
      str(datetime.datetime.now()))
    self.sqlexec(sql, locktable='ttest')
    sql = '''
select * from ttest
where edate >= '2011-06-24 09:28:12.345'
order by c1;
'''
    for row in self.sqlquery(sql):
      print row
    self.sqlclose()

if __name__ == '__main__':
  SSCCPP(sys.argv).process()
