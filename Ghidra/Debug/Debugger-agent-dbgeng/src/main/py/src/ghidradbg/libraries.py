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
from ghidradbg import dbgmodel


ctypes.windll.kernel32.SetErrorMode(0x0001 | 0x0002 | 0x8000)


try:
    from comtypes.gen import DbgMod
except:
    tlb = os.path.join(dbgmodel.module_locator(), 'tlb', 'dbgmodel.tlb')
    print(f"Loading TLB: {tlb}")
    comtypes.client.GetModule(tlb)
    from comtypes.gen import DbgMod
