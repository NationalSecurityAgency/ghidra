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
# Example of how to perform an overview query in a script
# @category BSim.python

import ghidra.features.bsim.query.facade.SFOverviewInfo as SFOverviewInfo
import ghidra.features.bsim.query.facade.SimilarFunctionQueryService as SimilarFunctionQueryService
import java.util.HashSet

SIMILARITY_BOUND = 0.7
SIGNIFICANCE_BOUND = 0.0

funcsToQuery = java.util.HashSet()
fIter = currentProgram.getFunctionManager().getFunctionsNoStubs(True)
for func in fIter:
   funcsToQuery.add(func.getSymbol())

overviewInfo = SFOverviewInfo(funcsToQuery)
overviewInfo.setSimilarityThreshold(SIMILARITY_BOUND)
overviewInfo.setSignificanceThreshold(SIGNIFICANCE_BOUND)

queryService = SimilarFunctionQueryService(currentProgram)
DB_URL = askString("Enter database URL", "URL:")
queryService.initializeDatabase(DB_URL)
vectorFactory = queryService.getLSHVectorFactory()

overviewResults = queryService.overviewSimilarFunctions(overviewInfo, None, monitor)

for result in overviewResults.result:
    print "Name: %s" % result.getBase().getFunctionName()
    print "Hit Count: %d" % result.getTotalCount()
    print "Self-significance: %f\n" % vectorFactory.getSelfSignificance(result.getBase().getSignatureRecord().getLSHVector())

queryService.dispose()
