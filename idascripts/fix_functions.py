# kernel is using stubs in the kexts

from idaapi import *
from idautils import *
from idc import *

def fix_stub(s):
  nam = get_segm_name(s)
  nam = nam.split("_")[0].split(".")[-1]
  for i in range(s, GetSegmentAttr(s, SEGATTR_END), 0x10):
    try:
      MakeFunction(i, i+0x10)
      fxn = DataRefsFrom(i).next()
      fxn = DataRefsFrom(fxn).next()
      print i, fxn, Name(fxn), nam
      if Name(fxn)[0:4] == "loc_" or Name(fxn)[0:4] == "sub_":
        continue
      newname = Name(fxn)+"_"+nam
      MakeName(i, newname)
      if GetType(fxn) != None:
        newtype = GetType(fxn).split("(")[0] + " " + newname + "(" + GetType(fxn).split("(")[1] + ";"
        SetType(i, newtype)
        print newtype
    except:
      pass

for s in Segments():
  nam = get_segm_name(s)
  if "__stub" in nam:
    #print nam
    #if "AppleMobileFileIntegrity" in nam:
    #if "sandbox" in nam:
    if 1:
      fix_stub(s)
