import sys
import os
import struct
import xml.dom.minidom as minidom

os.system("mkdir -p kexts")

if len(sys.argv) <= 1:
  print "usage: "+sys.argv[0]+" <decrypted kernelcache>"
  exit(-1)

kdat = open(sys.argv[1]).read()
d = 0


brks = []

def pp(di):
  for k in di:
    print "%40s %s" % (k,di[k])

while d != -1:
  d = kdat.find("\xce\xfa\xed\xfe", d+1)
  if d&0xFFF == 0:
    brks.append(d)

print "contains",len(brks),"kexts"
xmlstart = kdat.find("<dict><key>")
xmlend = kdat.rfind("</dict>") + 7

print "xml starts at",hex(xmlstart),hex(xmlend)
xml = kdat[xmlstart:xmlend]
open("out.xml", "wb").write(xml)
tree = minidom.parseString(xml)

kdi = []
for node in tree.childNodes[0].childNodes[1].childNodes:
  di = {}
  for i in range(0, len(node.childNodes), 2):
    try:
      di[node.childNodes[i].childNodes[0].nodeValue] = node.childNodes[i+1].childNodes[0].nodeValue
    except:
      pass
  # this is the jenk
  if '_PrelinkKmodInfo' not in di and '_PrelinkExecutableSize' not in di and '_PrelinkExecutableLoadAddr' not in di:
    continue
  kdi.append(di)


print "contains",len(kdi),"kext entries"

if len(kdi) != len(brks):
  print "THIS WILL FAIL"
  exit(-1)

brks.append(xmlstart)

for i in range(len(kdi)):
  di = kdi[i]
  name = di['CFBundleIdentifier']
  path = di['_PrelinkBundlePath']
  size = brks[i+1]-brks[i]
  if '_PrelinkExecutableSize' in di:
    size = int(di['_PrelinkExecutableSize'], 16)
  print hex(brks[i]), hex(size), name, path
  kext = kdat[brks[i]:brks[i]+size]
  open("kexts/"+path.split("/")[-1], "wb").write(kext)

exit(0)


