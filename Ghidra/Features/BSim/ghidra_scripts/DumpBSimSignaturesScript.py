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
# Generate the BSim signature for the function at the current address, then dump the 
# signature hashes to the console 
# @category: BSim.python

import ghidra.app.decompiler.DecompInterface as DecompInterface
import ghidra.app.decompiler.DecompileOptions as DecompileOptions
import generic.lsh.vector.WeightedLSHCosineVectorFactory as WeightedLSHCosineVectorFactory
import ghidra.features.bsim.query.GenSignatures as GenSignatures
import ghidra.xml.NonThreadedXmlPullParserImpl as NonThreadedXmlPullParserImpl
import ghidra.util.xml.SpecXmlUtils as SpecXmlUtils


def processFunction(func):
    decompiler = ghidra.app.decompiler.DecompInterface()
    try:
        options = ghidra.app.decompiler.DecompileOptions()
        decompiler.setOptions(options)
        decompiler.toggleSyntaxTree(False)
        decompiler.setSignatureSettings(getSettings())
        if not decompiler.openProgram(currentProgram):
            print "Unable to initialize the Decompiler interface!"
            print "%s" % decompiler.getLastMessage()
            return
        sigres = decompiler.generateSignatures(func, False, 10, None)
        buf = java.lang.StringBuffer()
        for i,res in enumerate(sigres.features):
            buf.append(java.lang.Integer.toHexString(sigres.features[i]))
            buf.append("\n")
        print buf.toString()
    finally:
        decompiler.closeProgram()
        decompiler.dispose()

def getSettings():
    vectorFactory = WeightedLSHCosineVectorFactory()
    id = currentProgram.getLanguageID()
    defaultWeightsFile = GenSignatures.getWeightsFile(id,id)
    input = defaultWeightsFile.getInputStream()
    parser = NonThreadedXmlPullParserImpl(input,"Vector weights parser", SpecXmlUtils.getXmlHandler(),False)
    vectorFactory.readWeights(parser)
    input.close()
    return vectorFactory.getSettings()

func = currentProgram.getFunctionManager().getFunctionContaining(currentAddress)
if func is None:
    print "no function at current address"
else:
    processFunction(func)
