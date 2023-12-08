/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//Example of a script to perform a more involved BSim query.
//@category BSim
import java.util.*;
import java.util.function.BiPredicate;

import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.gui.filters.*;
import ghidra.features.bsim.gui.search.results.BSimMatchResult;
import ghidra.features.bsim.gui.search.results.ExecutableResult;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.FunctionDatabase.ErrorCategory;
import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.features.bsim.query.facade.*;
import ghidra.features.bsim.query.protocol.BSimFilter;
import ghidra.features.bsim.query.protocol.PreFilter;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;

/**
 * Script showing how to apply filters to a BSim query. Currently we support three types
 * of filters, described below:
 * 
 * 	1. 	QUERY THRESHOLDS
 * 		These are the items at the top of the BSim query dialog:
 * 			Similarity
 * 			Confidence
 * 			Matches per Function
 * 		These are server-side filters that will be applied when the db is queried. 
 * 		
 * 2. 	PREFILTERS
 * 		Allows users to identify functions that meet certain criteria by specifying 
 * 		{@link BiPredicate}s. Any functions matching the predicate(s) will be included
 * 		in the result set.
 * 
 * 3. 	EXECUTABLE FILTERS
 * 		These are predefined filters that can be applied on the server or on the 
 * 		client (applied only to the results of a query). On the BSim query
 * 		dialog these are the items in the filter pulldown menu.
 * 		@see BSimFilterType
 *  
 *  SCRIPT FLOW
 *  	This example script does the following:
 *  
 *  	1) Set threshold filters
 *  	2) Set prefilters
 *  	3) Set executable filters
 *  	4) Query the database & print results
 *  	5) Set new executable filters
 *  	6) Print results
 *  
 *  NOTES:	1. 	You will be queried for the location of the BSim database. This URL
 *  			will take the form "ghidra://<ip address>/<database name>
 *  
 *  		2. 	This script is only an example - the specific filters demonstrated 
 *  			here will not necessarily apply to what's in your BSim database.
 *
 */
public class QueryWithFiltersScript extends GhidraScript {

	// Threshold settings.
	private static final int MAX_NUM_FUNCTIONS = 100;
	private static final double SIMILARITY_BOUND = 0.7;
	private static final double SIGNIFICANCE_BOUND = 0.0;

	// Restricts the number of results.
	private static final int NUM_EXES_TO_DISPLAY = 10;

	// Prefilter value we'll be setting.
	private static final double SELF_SIGNIFICANCE_BOUND = 40.0;

	private HashSet<FunctionSymbol> funcsToQuery;
	private SimilarFunctionQueryService queryService;
	private SFQueryInfo queryInfo;
	private BSimFilter bsimFilter;

	@Override
	protected void run() throws Exception {

		funcsToQuery = getFunctionsToQuery(currentProgram);
		queryService = new SimilarFunctionQueryService(currentProgram);
		queryInfo = new SFQueryInfo(funcsToQuery);
		bsimFilter = queryInfo.getBsimFilter();

		// Add threshold filters.
		queryInfo.setMaximumResults(MAX_NUM_FUNCTIONS);
		queryInfo.setSimilarityThreshold(SIMILARITY_BOUND);
		queryInfo.setSignificanceThreshold(SIGNIFICANCE_BOUND);

		// Add prefilters.
		setPrefilters();

		// Add a simple date filter.
		addBsimFilter(new DateLaterBSimFilterType(""), "01/01/1776");

		// Demonstration of a filter that allows for multiple entries. All filters but the 
		// DateEarlier and DateLater allow this. The effect is that each filter will be OR'd 
		// with the others. This is effectively the same as creating three distinct ArchEquals filters.
		//
		// ie: 	"The architecture can equal x86:LE:64:default OR the architecture can equal
		// 		ARM:LE_32:v4 OR ...."
		addBsimFilter(new ArchitectureBSimFilterType(),
			"x86:LE:64:default, x86:LE:32:default, ARM:LE:32:v4");

		// Another filter with multiple entries, but in this case since it is a "NotEqual" filter,
		// the items are "AND'd together.
		// 
		// ie: "The compiler cannot equal windows AND the compiler cannot equal foo_compiler".
		addBsimFilter(new NotCompilerBSimFilterType(), "windows, foo_compiler");

		//connect to the database
		try {
			String dbUrl =
				askString("", "Enter the URL of the BSim database:", "ghidra://localhost/bsimDb");
			queryService.initializeDatabase(dbUrl);
			FunctionDatabase.Error error = queryService.getLastError();
			if (error != null && error.category == ErrorCategory.Nodatabase) {
				println("Database [" + dbUrl + "] cannot be found (does it exist?)");
				return;
			}
		}
		catch (QueryDatabaseException e) {
			println(e.getMessage());
			return;
		}

		// Execute query and print results.
		List<BSimMatchResult> resultRows = executeQuery(queryInfo);
		printFunctionQueryResults(resultRows, "\nFunction-level results before filtering");

		// Add some simple post-query filters. These filters will only be applied to the result
		// set returned from the previous query.
		addBsimFilter(new Md5BSimFilterType(), currentProgram.getExecutableMD5());
		addBsimFilter(new CompilerBSimFilterType(), "gcc");
		//addBsimFilter(new FunctionTagBSimFilterType("KNOWN_LIBRARY", queryService), "false");

		// Apply the filters and print results.
		List<BSimMatchResult> filteredRows =
			BSimMatchResult.filterMatchRows(bsimFilter, resultRows);
		printFunctionQueryResults(filteredRows, "\nFunction-level results after filtering");
		printExecutableInformation(filteredRows);
	}

	@Override
	public void cleanup(boolean success) {
		if (queryService != null) {
			queryService.dispose();
		}
	}

	/***********************************************************************
	 * PRIVATE METHODS
	 ***********************************************************************/

	/**
	 * Adds a filter to the given filter container.
	 * 
	 * @param filterTemplate the filter type to add
	 * @param value the value of the filter
	 */
	private void addBsimFilter(BSimFilterType filterTemplate, String value) {
		String[] inputs = value.split(",");
		for (String input : inputs) {
			if (!input.trim().isEmpty()) {
				bsimFilter.addAtom(filterTemplate, input.trim());
			}
		}
	}

	/**
	 * Queries the database and returns the results. 
	 * 
	 * @param qInfo contains all information required for the query
	 * @return list of matches
	 * @throws QueryDatabaseException if there is a problem executing the query similar functions query
	 * @throws CancelledException if the user cancelled the operation
	 */
	private List<BSimMatchResult> executeQuery(SFQueryInfo qInfo)
			throws QueryDatabaseException, CancelledException {

		SFQueryResult queryResults = queryService.querySimilarFunctions(qInfo, null, monitor);
		List<BSimMatchResult> resultRows =
			BSimMatchResult.generate(queryResults.getSimilarityResults(), currentProgram);

		return resultRows;
	}

	/**
	 * Creates predicates that will be used to filter out functions. This example provides three
	 * different methods of doing this:
	 * 
	 * - anonymous class
	 * - lambda
	 * - static method
	 * 
	 * These are all possible because the filter takes a {@link BiPredicate}, which is a 
	 * functional interface.
	 * 
	 */
	private void setPrefilters() {

		PreFilter preFilter = queryInfo.getPreFilter();

		//
		// Option 1: 	Anonymous class
		//				Filters out any functions with a self significance less than a 
		//				certain value.
		//
		preFilter.addPredicate(new BiPredicate<Program, FunctionDescription>() {
			@Override
			public boolean test(Program t, FunctionDescription u) {
				return queryService.getLSHVectorFactory()
						.getSelfSignificance(
							u.getSignatureRecord().getLSHVector()) >= SELF_SIGNIFICANCE_BOUND;
			}
		});

		//
		// Option 2. 	Lambda expression
		//				Filters out any functions with a self significance less than a 
		//				certain value.
		//
		preFilter.addPredicate((x,
				y) -> queryService.getLSHVectorFactory()
						.getSelfSignificance(
							y.getSignatureRecord().getLSHVector()) >= SELF_SIGNIFICANCE_BOUND);

		//
		// Option 3. 	Static method
		//				Filters out any functions that are of type ANALYSIS.
		//
		preFilter.addPredicate(QueryWithFiltersScript::isNotAnalysisSourceType);
	}

	/**
	 * Returns a set of ALL functions (no stubs) in the given program.
	 * 
	 * @param program the program to get the functions from
	 * @return list of function symbols
	 */
	private HashSet<FunctionSymbol> getFunctionsToQuery(Program program) {
		HashSet<FunctionSymbol> functions = new HashSet<>();
		FunctionIterator fIter = program.getFunctionManager().getFunctionsNoStubs(true);
		for (Function func : fIter) {
			functions.add((FunctionSymbol) func.getSymbol());
		}
		return functions;
	}

	/**
	 * Returns true if the given function is NOT an analysis type.
	 * 
	 * @param program the current program
	 * @param funcDesc the function description object
	 * @return true if the symbol is NOT an analysis source type
	 */
	public static boolean isNotAnalysisSourceType(Program program, FunctionDescription funcDesc) {
		Address address =
			program.getAddressFactory().getDefaultAddressSpace().getAddress(funcDesc.getAddress());

		Function function = program.getFunctionManager().getFunctionAt(address);
		if (function == null || !function.getName().equals(funcDesc.getFunctionName())) {
			return false;
		}
		return function.getSymbol().getSource() != SourceType.ANALYSIS;
	}

	/**
	 * Prints a sorted list of executables represented in the function matches.
	 * 
	 * @param filteredRows list of function results
	 */
	private void printExecutableInformation(List<BSimMatchResult> filteredRows) {

		TreeSet<ExecutableResult> execrows = ExecutableResult.generateFromMatchRows(filteredRows);
		ExecutableResult[] results = new ExecutableResult[execrows.size()];
		results = execrows.toArray(results);

		Arrays.sort(results, new Comparator<ExecutableResult>() {
			@Override
			public int compare(ExecutableResult o1, ExecutableResult o2) {
				return Double.compare(o2.getSignificanceSum(), o1.getSignificanceSum());
			}
		});

		printf("Executable-level results:\n");
		for (int i = 0, max = Math.min(NUM_EXES_TO_DISPLAY, results.length); i < max; ++i) {
			printf("  MD5: %s\n", results[i].getExecutableRecord().getMd5());
			printf("  Executable Name: %s\n", results[i].getExecutableRecord().getNameExec());
			printf("  Function Count: %d\n", results[i].getFunctionCount());
			printf("  Significance Sum: %f\n\n", results[i].getSignificanceSum());
		}
	}

	/**
	 * Prints information about each function in the result set.
	 * 
	 * @param resultRows the list of rows containing the info to print
	 * @param title the title to print
	 */
	private void printFunctionQueryResults(List<BSimMatchResult> resultRows, String title) {
		printf(title + ": (%d)\n\n", resultRows.size());
		for (BSimMatchResult resultRow : resultRows) {
			printf("  queried function: %s\n",
				resultRow.getOriginalFunctionDescription().getFunctionName());
			printf("  matching function: %s\n",
				resultRow.getMatchFunctionDescription().getFunctionName());
			printf("  executable of matching function: %s\n",
				resultRow.getMatchFunctionDescription().getExecutableRecord().getNameExec());
			printf("  similarity: %f\n", resultRow.getSimilarity());
			printf("  significance: %f\n\n", resultRow.getSignificance());
		}
		printf("\n");
	}

}
