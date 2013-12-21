# omg who can code in not python
import sys
import os
from hexdump import hexdump
import struct
import hashlib

fn = sys.argv[1] if len(sys.argv) > 1 else "app"
# parse with otool

os.system("codesign -dvvv "+fn)
os.system("otool -l "+fn+" > loads")
a = open("loads").read().split("Load command ")
dat = open(fn).read()

segs = []
for i in a[1:]:
  dic = {}
  for cc in i.split("\n")[1:-1]:
    ldat = cc.strip()
    sp = ldat.find(" ")
    dic[ldat[0:sp]] = ldat[sp+1:]
  segs.append(dic)

"""
/*
 * C form of a CodeDirectory.
 */
typedef struct __CodeDirectory {
  uint32_t magic;         /* magic number (CSMAGIC_CODEDIRECTORY) */
  uint32_t length;        /* total length of CodeDirectory blob */
  uint32_t version;       /* compatibility version */
  uint32_t flags;         /* setup and mode flags */
  uint32_t hashOffset;      /* offset of hash slot element at index zero */
  uint32_t identOffset;     /* offset of identifier string */
  uint32_t nSpecialSlots;     /* number of special hash slots */
  uint32_t nCodeSlots;      /* number of ordinary (code) hash slots */
  uint32_t codeLimit;       /* limit to main image signature range */
  uint8_t hashSize;       /* size of each hash in bytes */
  uint8_t hashType;       /* type of hash (cdHashType* constants) */
  uint8_t spare1;         /* unused (must be zero) */
  uint8_t pageSize;       /* log2(page size in bytes); 0 => infinite */
  uint32_t spare2;        /* unused (must be zero) */
  /* Version 0x20100 */
  uint32_t scatterOffset;       /* offset of optional scatter vector */
  /* followed by dynamic content as located by offset fields above */
} CS_CodeDirectory;
"""

# LC_CODE_SIGNATURE
# 4 bytes magic
# 4 bytes length
def parse_cs(cs):
  CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0
  CSMAGIC_CODEDIRECTORY = 0xfade0c02
  CSMAGIC_REQUIREMENTS = 0xfade0c01
  CSMAGIC_BLOBWRAPPER = 0xfade0b01

  (magic, l, count) = struct.unpack(">III", cs[0:0xC])
  print "%x %x" % (magic, l)
  #hexdump(cs[0:0x20])

  if magic == CSMAGIC_EMBEDDED_SIGNATURE:
    sects = []
    for i in range(count):
      sects.append(struct.unpack(">II", cs[0xC+i*8:0xC+i*8+8]))
    sects.append((-1, l))
    for i in range(len(sects)-1):
      (typ, offset) = sects[i]
      print typ, hex(offset)
      parse_cs(cs[offset:sects[i+1][1]])

  if magic == CSMAGIC_CODEDIRECTORY:
    hexdump(cs)
    print "CDHash", hashlib.sha1(cs).hexdigest()
    (magic, length, version, flags, hashOffset, identOffset, nSpecialSlots, nCodeSlots, codeLimit, hashSize, hashType, spare1, pageSize, spare2, scatterOffset) = struct.unpack(">IIIIIIIIIBBBBII", cs[0:12*4])
    print nSpecialSlots, nCodeSlots
    print hex(codeLimit)
    page = 0
    pagesize = 1 << pageSize
    for i in range(nCodeSlots):
      has = cs[hashOffset + i*hashSize:hashOffset + i*hashSize + hashSize]
      end = min(codeLimit, page+pagesize)
      rhash = hashlib.sha1(dat[page:end])
      print has.encode("hex"), rhash.hexdigest()
      if has != rhash.digest():
        print "BAD SIGN!!!!"
      page += pagesize


for i in segs:
  if 'dataoff' in i:
    dataoff = int(i['dataoff'])
    datasize = int(i['datasize'])
    print i['cmd'], hex(dataoff), hex(datasize)
    if i['cmd'] == "LC_CODE_SIGNATURE":
      parse_cs(dat[dataoff:dataoff+datasize])
    else:
      hexdump(dat[dataoff:dataoff+datasize])


