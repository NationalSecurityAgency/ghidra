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
# Generate the BSim signature for the function at the current address, 
# then dump the signature hashes and debug information to the console
# @category: BSim.python

import ghidra.app.decompiler.DecompInterface as DecompInterface
import ghidra.app.decompiler.DecompileOptions as DecompileOptions

def processFunction(func):
    decompiler = DecompInterface()
    try:
        options = DecompileOptions()
        decompiler.setOptions(options)
        decompiler.toggleSyntaxTree(False)
        decompiler.setSignatureSettings(0x4d)
        if not decompiler.openProgram(currentProgram):
            print "Unable to initialize the Decompiler interface!"
            print "%s" % decompiler.getLastMessage()
            return
        language = currentProgram.getLanguage()
        sigres = decompiler.debugSignatures(func,10,None)
        for i,res in enumerate(sigres):
            buf = java.lang.StringBuffer()
            sigres.get(i).printRaw(language,buf)
            print "%s" % buf.toString()
    finally:
        decompiler.closeProgram()
        decompiler.dispose()

func = currentProgram.getFunctionManager().getFunctionContaining(currentAddress)
if func is None:
    print "no function at current address"
else:
    processFunction(func)
