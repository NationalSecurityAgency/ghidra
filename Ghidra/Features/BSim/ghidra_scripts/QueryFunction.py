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
# Example of performing a BSim query on a single function
# @category BSim.python  

import ghidra.features.bsim.query.BSimClientFactory as BSimClientFactory
import ghidra.features.bsim.query.GenSignatures as GenSignatures
import ghidra.features.bsim.query.protocol.QueryNearest as QueryNearest

MATCHES_PER_FUNC = 100
SIMILARITY_BOUND = 0.7
CONFIDENCE_BOUND = 0.0

def query(func):
    DATABASE_URL = askString("Enter Database URL", "URL")
    url = BSimClientFactory.deriveBSimURL(DATABASE_URL)
    database = BSimClientFactory.buildClient(url,False)
    if not database.initialize():
        print database.getLastError().message
        return
    gensig = GenSignatures(False)
    gensig.setVectorFactory(database.getLSHVectorFactory())
    gensig.openProgram(currentProgram,None,None,None,None,None)
    
    gensig.scanFunction(func)

    query = QueryNearest()
    query.manage = gensig.getDescriptionManager()
    query.max = MATCHES_PER_FUNC
    query.thresh = SIMILARITY_BOUND
    query.signifthresh = CONFIDENCE_BOUND

    response = database.query(query)
    if response is None:
        print database.getLastError().message
        return
    simIter = response.result.iterator()
    while simIter.hasNext():
        sim = simIter.next()
        base = sim.getBase()
        exe = base.getExecutableRecord()
        print "Source executable: %s; source function: %s" % (exe.getNameExec(),base.getFunctionName())
        subIter = sim.iterator()
        while subIter.hasNext():
            note = subIter.next()
            fdesc = note.getFunctionDescription()
            exerec = fdesc.getExecutableRecord()
            print "  Executable: %s" % exerec.getNameExec()
            print "  Matching Function name: %s " % fdesc.getFunctionName()
            print "  Similarity: %f" % note.getSimilarity()
            print "  Significance: %f\n" % note.getSignificance()
    gensig.dispose()
    database.close()
    return;

if currentProgram is None:
    popup("currentProgram is None!")
else:
    func = currentProgram.getFunctionManager().getFunctionContaining(currentAddress)
    if func is None:
        popup("Cursor must be in a function!")
    else:
        query(func)


