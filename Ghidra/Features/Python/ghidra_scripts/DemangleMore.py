# Attempts to more aggressively demangle any Microsoft-style mangled symbols.
# DemanglerCmd is not used as it will filter by program format (e.g. Microsoft
# Demangler will not be used if the executable format is not PE/COFF). Instead,
# this script invokes the MicrosoftDemangler directly on any symbol prefixed by
# `?`. Additionally, this script handles `@name@X` (fastcall) and `_name@X`
# (stdcall) mangles.
# @author: Matt Borgerson
# @category: Symbol
from ghidra.app.util.demangler import DemanglerOptions
from ghidra.app.util.demangler.microsoft import MicrosoftDemangler
from ghidra.program.model.symbol import SourceType
import re

st = currentProgram.getSymbolTable()
n = currentProgram.getNamespaceManager().getGlobalNamespace()

numDemangled = 0
failures = []

for s in st.getSymbols(n):
  name = s.getName()
  addr = s.getAddress()

  if name.startswith('?'):
    # Attempt using Microsoft demangler
    try:
      print('Demangling with Microsoft Demangler: %s' % name)
      demangled = MicrosoftDemangler().demangle(name, True)
      s.delete()
      demangled.applyTo(currentProgram, addr, DemanglerOptions(), monitor)
    except:
      print('Failed to demangle %s' % name)
      failures.append(name)

  elif name.startswith('@') or name.startswith('_'):
    # Attempt decoding @func@0 (__fastcall) and _func@0 (__stdcall) style mangle
    # https://en.wikipedia.org/wiki/Name_mangling#Standardised_name_mangling_in_C++
    isFastcall, isStdcall = False, False
    realName, bytesInParams = '', 0

    m = re.match('^@(\w+)@([0-9]+)$', name)
    if m is not None:
      isFastcall = True
      realName, bytesInParams = m.groups()
    else:
      m = re.match('^_(\w+)@([0-9]+)$', name)
      if m is not None:
        isStdcall = True
        realName, bytesInParams = m.groups()

    if isFastcall or isStdcall:
      print('Demangling: %s' % name)
      bytesInParams = int(bytesInParams)

      # Get or create the function
      s.delete()
      f = getFunctionAt(addr)
      if f is None:
        f = createFunction(addr, realName)

      if f is None:
        print('Couldn\'t create function for %s' % realName)
        failures.append(name)
      else:
        f.setName(realName, SourceType.ANALYSIS)
        f.setComment(name)
        convention = '__fastcall' if isFastcall else '__stdcall'
        f.setCallingConvention(convention)
  else:
    continue

  numDemangled += 1

print('Demangled %d names' % numDemangled)
if len(failures) > 0:
  print('Failed to demangle (%d):' % len(failures))
  for n in sorted(failures):
    print('- %s' % n)
