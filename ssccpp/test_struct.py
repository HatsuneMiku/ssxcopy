#!/usr/local/bin/python
# -*- coding: utf-8 -*-
'''test_struct
'''

import struct

def main():
  print 'default (as machine endian)'
  print repr(struct.pack('hhl', 1, 2, 3))
  print struct.unpack('hhl', '\x00\x01\x00\x02\x00\x00\x00\x03')
  print struct.calcsize('hhl')

  print 'big endian'
  print repr(struct.pack('>hhl', 1, 2, 3))
  print struct.unpack('>hhl', '\x00\x01\x00\x02\x00\x00\x00\x03')
  print struct.calcsize('>hhl')

  print 'little endian'
  print repr(struct.pack('<hhl', 1, 2, 3))
  print struct.unpack('<hhl', '\x00\x01\x00\x02\x00\x00\x00\x03')
  print struct.calcsize('<hhl')

if __name__ == '__main__':
  main()
