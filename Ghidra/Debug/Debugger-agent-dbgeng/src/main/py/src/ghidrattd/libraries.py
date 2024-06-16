## ###
#  IP: GHIDRA
# 
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  
#       http://www.apache.org/licenses/LICENSE-2.0
#  
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
##
import ctypes
import os
import platform

import comtypes
import comtypes.client


ctypes.windll.kernel32.SetErrorMode(0x0001 | 0x0002 | 0x8000)

if platform.architecture()[0] == '64bit':
    dbgdirs = [os.getenv('OPT_DBGMODEL_PATH'),
               r'C:\Program Files\Windows Kits\10\Debuggers\x64',
               r'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64']
else:
    dbgdirs = [os.getenv('OPT_DBGMODEL_PATH'),
               r'C:\Program Files\Windows Kits\10\Debuggers\x86',
               r'C:\Program Files (x86)\Windows Kits\10\Debuggers\x86']
dbgdir = None
for _dir in dbgdirs:
    if _dir is not None and os.path.exists(_dir):
        dbgdir = _dir
        break

if not dbgdir:
    raise RuntimeError("Windbg install directory not found!")

print(f"Loading dbgeng and friends from {dbgdir}")

# preload these to get correct DLLs loaded
try:
    ctypes.windll.LoadLibrary(os.path.join(dbgdir, 'dbghelp.dll'))
except Exception as exc:
    print(fr"LoadLibrary failed: {dbgdir}\dbghelp.dll {exc}")
    pass
try:
    ctypes.windll.LoadLibrary(os.path.join(dbgdir, 'dbgeng.dll'))
except Exception as exc:
    print(fr"LoadLibrary failed: {dbgdir}\dbgeng.dll {exc}")
    pass
try:
    ctypes.windll.LoadLibrary(os.path.join(dbgdir, 'DbgModel.dll'))
except Exception as exc:
    print(fr"LoadLibrary failed: {dbgdir}\dbgmodel.dll {exc}")
    pass
try:
    ctypes.windll.LoadLibrary(os.path.join(dbgdir, 'ttd/TTDReplay.dll'))
except Exception as exc:
    print(fr"LoadLibrary failed: {dbgdir}\ttd\TTDReplay.dll {exc}")
    pass
try:
    ctypes.windll.LoadLibrary(os.path.join(dbgdir, 'ttd/TTDReplayCPU.dll'))
except Exception as exc:
    print(fr"LoadLibrary failed: {dbgdir}\ttd\TTDReplayCPU.dll {exc}")
    pass

try:
    from comtypes.gen import DbgMod
except:
    tlb = os.path.join(dbgmodel.module_locator(), 'tlb', 'dbgmodel.tlb')
    print(f"Loading TLB: {tlb}")
    comtypes.client.GetModule(tlb)
    from comtypes.gen import DbgMod
