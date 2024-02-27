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
from . import util, commands, methods, hooks
from dbgmodel.ihostdatamodelaccess import HostDataModelAccess
import ctypes
import platform
import os


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
    if os.path.exists(_dir):
        dbgdir = _dir
        break

if not dbgdir:
    raise RuntimeError("Windbg install directory not found!")

# preload these to get correct DLLs loaded
try:
    ctypes.windll.LoadLibrary(os.path.join(dbgdir, 'dbghelp.dll'))
except Exception as exc:
    print(f"LoadLibrary failed: {dbgdir}\dbghelp.dll {exc}")
    pass
try:
    ctypes.windll.LoadLibrary(os.path.join(dbgdir, 'dbgeng.dll'))
except Exception as exc:
    print(f"LoadLibrary failed: {dbgdir}\dbgeng.dll {exc}")
    pass
try:
    ctypes.windll.LoadLibrary(os.path.join(dbgdir, 'DbgModel.dll'))
except Exception as exc:
    print(f"LoadLibrary failed: {dbgdir}\dbgmodel.dll {exc}")
    pass
