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
# Advanced example of BSim querying
# @category BSim.python

import ghidra.query.facade.SimilarFunctionQueryService as SimilarFunctionQueryService
import ghidra.query.facade.SFQueryInfo as SFQueryInfo
import ghidra.query.FunctionDatabase as FunctionDatabase
import ghidra.query.facade.QueryDatabaseException as QueryDatabaseException
import java.util.HashSet as HashSet
import ghidra.app.plugin.core.query.QueryNearestRow as QueryNearestRow
import java.util.function.BiPredicate as BiPredicate
import ghidra.query.protocol.FilterTemplate as FilterTemplate
import ghidra.app.plugin.core.query.ExecutableResult as ExecutableResult
import java.util.Comparator as Comparator
import java.util.Arrays as Arrays
import java.lang.Double as Double

#Query thresholds
MAX_NUM_FUNCTIONS = 100
SIMILARITY_BOUND = 0.7
SIGNIFICANCE_BOUND = 0.0

#limit the number of results displayed
NUM_EXES_TO_DISPLAY = 10

#for prefiltering: this number will be used to filter out small functions
SELF_SIGNIFICANCE_BOUND = 40.0

def run():

    #get the set of functions to query
    funcsToQuery = getFunctionsToQuery()

    #sets up the object required for querying the database
    queryService = SimilarFunctionQueryService(currentProgram)    
    queryInfo = SFQueryInfo(funcsToQuery)
    bsimFilter = queryInfo.getBsimFilter()

    #sets the query parameters.  
    #change the defined constants to control how fuzzy of
    #a match you're willing to accept, and the maximum number
    #of matches to return for each function
    queryInfo.setMaximumResults(MAX_NUM_FUNCTIONS)
    queryInfo.setSimilarityThreshold(SIMILARITY_BOUND)
    queryInfo.setSignificanceThreshold(SIGNIFICANCE_BOUND)

    #add the prefilters
    setPrefilters(queryService, queryInfo)

    #add a filter on the date
    addBsimFilter(bsimFilter, FilterTemplate.DateLater(""), "01/01/1776")

    #add a filter with multiple values.  Since this is an "Equal" filter, the results are OR'd together
    #so a given executable will pass the main filter if it passes at least one of the subfilters
    addBsimFilter(bsimFilter, FilterTemplate.ArchEquals(),"x86:LE:64:default, x86:LE:32:default, ARM:LE:32:v4")   

    #now add a "notequal" filter
    #to pass, the compiler can't be windows and it can't be foo_compiler
    addBsimFilter(bsimFilter,FilterTemplate.CompNotEqual(),"windows, foo_compiler")
 
    #establish a connection to the BSim database
    try:
        dbUrl = askString("","Enter the URL of the BSim database:", "ghidra://localhost/bsimDB")
        queryService.initializeDatabase(dbUrl)
        error = queryService.getDatabase().getLastError()
        if error is not None and (error.category is ErrorCategory.Nodatabase):
            print "Database [%s] cannot be found (does it exist?)" % dbUrl
            return
    except QueryDatabaseException as e:
        print e.getMessage()
        return

    resultRows = executeQuery(queryService,queryInfo)
    printFunctionQueryResults(resultRows, "\nFunction-level results before filtering")

    #now add some post-query filters, which filters the result set returned by the previous query

    addBsimFilter(bsimFilter, FilterTemplate.Md5NotEqual(), currentProgram.getExecutableMD5())
    addBsimFilter(bsimFilter, FilterTemplate.CompilerEquals(), "gcc")
    addBsimFilter(bsimFilter, FilterTemplate.FunctionTagTemplate("KNOWN_LIBRARY", queryService), "false")

    #apply the filters and print the results
    filteredRows = QueryNearestRow.filterMatchRows(bsimFilter, resultRows)
    printFunctionQueryResults(filteredRows, "\nFunction-level results after filtering")
    printExecutableInformation(filteredRows)
    return


#collect the functions to query from currentProgram
def getFunctionsToQuery():
    functions = HashSet();
    fIter = currentProgram.getFunctionManager().getFunctionsNoStubs(True)
    for func in fIter:
        functions.add(func.getSymbol())
    return functions
    
#query the database
def executeQuery(queryService,queryInfo):
    queryResults = queryService.querySimilarFunctions(queryInfo,monitor)
    resultRows = QueryNearestRow.generate(queryResults.getSimilarityResults(),currentProgram)
    return resultRows

def printFunctionQueryResults(resultRows, title):
    print "%s: %d\n\n" % (title, resultRows.size())
    for row in resultRows:
        print "  queried function: %s" % row.getOriginalFunctionDescription().getFunctionName()
        print "  matching function: %s" % row.getMatchFunctionDescription().getFunctionName()
        print "  executable of matching function: %s" % row.getMatchFunctionDescription().getExecutableRecord().getNameExec()
        print "  similarity: %f" % row.getSimilarity()
        print "  significance: %f\n" % row.getSignificance()

#Prefilters are used to filter out functions before sending a query to the database
#A typical use case would be to collect all functions in a binary, then use a 
#prefilter to remove the functions with low self-significance (which is the 
#"BSim way" to remove small functions)
def setPrefilters(queryService, queryInfo):
    preFilter = queryInfo.getPreFilter();
    selfSigFilter = ExampleFilter(queryService)
    preFilter.addPredicate(selfSigFilter)

class ExampleFilter(BiPredicate):
   
    def __init__(self, queryService):
        self.queryService = queryService

    def test(self,program, fdesc):
        return self.queryService.getLSHVectorFactory().getSelfSignificance(fdesc.getSignatureRecord().getLSHVector()) >= SELF_SIGNIFICANCE_BOUND

def addBsimFilter(bsimFilter, filterTemplate, values):
    for value in values.split(","):
        if len(value.strip()) > 0:
            bsimFilter.addAtom(filterTemplate, value.strip(), FilterTemplate.Blank())

#calls the methods to aggregate executable-level information about the matches 
def printExecutableInformation(filteredRows):
    execrows = ExecutableResult.generateFromMatchRows(filteredRows)
    results = execrows.toArray()
    sorter = Sorter()
    Arrays.sort(results,sorter) 
    print "Executable-level results:"
    numExes = min(len(results),NUM_EXES_TO_DISPLAY)
    for i in range (numExes):
        print "  MD5: %s" % results[i].getExecutableRecord().getMd5()
        print "  Executable Name: %s" % results[i].getExecutableRecord().getNameExec()
        print "  Function Count: %d" % results[i].getFunctionCount()
        print "  Significance Sum: %f\n" % results[i].getSignificanceSum()
    return

class Sorter(Comparator):

    def __init__(self):
        return
    
    def compare(self,o1,o2):
        return Double.compare(o2.getSignificanceSum(), o1.getSignificanceSum()) 



run()
