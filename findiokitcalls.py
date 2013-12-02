import sys
import os
import struct


def search_file(f):
  print "searching",f
  d = open(f).read()
  iostart = 0
  iolen = 0
  iolastreset = 0
  rc = 0

  for rf in range(0, 0x14, 4):
    for add in range(0, len(d)-0x24, 0x14):
      addr = add+rf
      (fxn, flag, i, un, o) = struct.unpack("IIIII", d[addr:addr+0x14])
      cnt = 0
      cnt += 2 * (fxn > 0x80000000 and fxn < 0x81000000)
      cnt += (flag < 20) or (flag >= 4294967295)
      cnt += (i < 0x2000 or i == 0xFFFFFFFF)
      cnt += (un < 10)
      cnt += (o < 0x2000 or o == 0xFFFFFFFF)
      #cnt += (rc > 0)
      if cnt >= 6:
        #print "found at", addr, rc
        if rc == 0:
          iolastreset = addr
        rc += 1
      else:
        if rc > iolen:
          iolen = rc
          iostart = iolastreset
        rc = 0

  if iolen >= 3:
    print "start",iostart,"len",iolen

    for addr in range(iostart, iostart+iolen*0x14, 0x14):
      (fxn, flag, i, un, o) = struct.unpack("Iiiii", d[addr:addr+0x14])
      print "0x%X %3d %4d %3d %4d" % (fxn, flag, i, un, o)

for f in sys.argv[1:]:
  search_file(f)




