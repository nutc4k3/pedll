import pefile
import sys

exe_path = sys.argv[1]
pe = pefile.PE(exe_path)

aslr = pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
dep = pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NX_COMPAT
safeseh = pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_SEH

def check():
    print("ASLR\t\t: " + str(aslr))
    print("DEP\t\t: " + str(dep))
    print("SafeSEH\t\t: "+str(safeseh))

def disable():
    print( "Disabling protections")
    pe.OPTIONAL_HEADER.DllCharacteristics = 32768
    pe.write(filename='zoom_patched.exe')
    print("Pronto --> " + hex(pe.OPTIONAL_HEADER.DllCharacteristics))

check()
disable()
