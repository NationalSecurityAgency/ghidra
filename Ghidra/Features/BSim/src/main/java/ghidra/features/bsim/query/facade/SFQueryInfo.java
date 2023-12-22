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
package ghidra.features.bsim.query.facade;

import java.util.*;

import ghidra.features.bsim.query.protocol.*;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.listing.Program;

/**
 * A simple container object to hold information that is to be sent to a database server as
 * part of a query to find functions that are similar to those given in the constructor of this
 * class.  For a list of configurable parameters, see the setter methods of this class.
 */
public class SFQueryInfo {

	/**
	 * The number of queries to make for the given set of functions.  For example, if 100 functions
	 * are submitted and the number of stages is 10, then 10 queries will be made to the server, 
	 * with 10 functions per request.
	 * <P>
	 * This defaults to 1, which means to send all functions in one query.
	 */
	public static final int DEFAULT_QUERIES_PER_STAGE = 10;

	private Set<FunctionSymbol> functions;
	private Program program;

	private QueryNearest queryNearest;
	private BSimFilter bsimFilter;
	private PreFilter preFilter;

	/**
	 * Constructs a query request with default parameters.
	 * @param functions required--a set of functions (at least one) for which similar functions
	 *                  will searched.  All functions must be from the same program.
	 * @throws IllegalArgumentException if <tt>functions</tt> is <tt>null</tt>/empty or functions
	 * are from multiple programs.  
	 */
	public SFQueryInfo(Set<FunctionSymbol> functions) {
		if (functions == null) {
			throw new IllegalArgumentException("Function list cannot be null");
		}

		if (functions.isEmpty()) {
			throw new IllegalArgumentException("Function list cannot be empty");
		}

		this.functions = functions;
		for (FunctionSymbol s : functions) {
			if (program == null) {
				program = s.getProgram();
			}
			else if (program != s.getProgram()) {
				throw new IllegalArgumentException(
					"all function symbols are not from the same program");
			}
		}
		queryNearest = new QueryNearest();
		bsimFilter = new BSimFilter();
		preFilter = new PreFilter();
	}

	/**
	 * @return the program from which all queried functions are from
	 */
	public Program getProgram() {
		return program;
	}

	/**
	 * Gets the threshold under which a potential similar function will not be matched.  This
	 * threshold is for how similar the potential function is. This is a value from 0.0 to 1.0. The 
	 * default value is {@value QueryNearest#DEFAULT_SIMILARITY_THRESHOLD}.
	 * 
	 * @return threshold under which a potential similar function will not be matched.
	 */
	public double getSimilarityThreshold() {
		return queryNearest.thresh;
	}

	/**
	 * @see #getSimilarityThreshold()
	 * @param similarityThreshold the new threshold
	 */
	public void setSimilarityThreshold(double similarityThreshold) {
		queryNearest.thresh = similarityThreshold;
	}

	/**
	 * Gets the threshold under which a potential similar function will not be matched.  This
	 * threshold is for how significant the match is (for example, smaller function matches
	 * are less significant).  Higher is more significant.  There is no upper bound. The 
	 * default value is {@value QueryNearest#DEFAULT_SIGNIFICANCE_THRESHOLD}.
	 * 
	 * @return threshold under which a potential similar function will not be matched.
	 */
	public double getSignificanceThreshold() {
		return queryNearest.signifthresh;
	}

	/**
	 * @see #getSignificanceThreshold()
	 * @param significanceThreshold the new threshold
	 */
	public void setSignificanceThreshold(double significanceThreshold) {
		queryNearest.signifthresh = significanceThreshold;
	}

	/**
	 * The maximum number of similar functions to return <b>for a given input function</b>
	 * The default value is {@value QueryNearest#DEFAULT_MAX_MATCHES}.
	 *  
	 * @return The maximum number of similar functions to return
	 */
	public int getMaximumResults() {
		return queryNearest.max;
	}

	/**
	 * @see #getMaximumResults()
	 * @param maximumResults the new maximum
	 */
	public void setMaximumResults(int maximumResults) {
		queryNearest.max = maximumResults;
	}

	public QueryNearest buildQueryNearest() {
		if (bsimFilter.isEmpty()) {
			queryNearest.bsimFilter = null;
		}
		else {
			queryNearest.bsimFilter = bsimFilter;
		}
		return queryNearest;
	}

	/**
	 * Returns the input functions for which matches will be searched.
	 * @return the input functions for which matches will be searched.
	 */
	public Set<FunctionSymbol> getFunctions() {
		return functions;
	}

	/**
	 * Sets the input functions for which matches will be searched.
	 * @param functions the input functions for which matches will be searched.
	 */
	public void setFunctions(Set<FunctionSymbol> functions) {
		this.functions = functions;
	}

	public BSimFilter getBsimFilter() {
		return bsimFilter;
	}

	public PreFilter getPreFilter() {
		return preFilter;
	}

	public Collection<String> getFilterInfoStrings() {
		List<String> arrlist = new ArrayList<String>();
		for (int i = 0; i < bsimFilter.numAtoms(); ++i) {
			FilterAtom atom = bsimFilter.getAtom(i);
			String str = atom.getInfoString();
			if (str != null) {
				arrlist.add(str);
			}
		}
		return arrlist;
	}

	/**
	 * The number of queries to make for the given set of functions.  For example, if 100 functions
	 * are submitted and the number of stages is 10, then 10 queries will be made to the server, 
	 * with 10 functions per request.
	 * <P>
	 * This defaults to 1, which means to send all functions in one query.
	 * @param queries_per_stage how many queries to initiate per stage
	 * 
	 * @return the number of queries to make for the given set of functions.
	 */
	public int getNumberOfStages(int queries_per_stage) {
		if ((functions == null) || (functions.size() == 0)) {
			return 1;
		}
		if (queries_per_stage == 0) {
			queries_per_stage = DEFAULT_QUERIES_PER_STAGE;
		}
		return (functions.size() + (queries_per_stage - 1)) / queries_per_stage;
	}

	@Override
	public String toString() {
		// @formatter:off
		return getClass().getSimpleName() + 
				"\n\tsimilarity: " + queryNearest.thresh + 
				"\n\tsignificance: " + queryNearest.signifthresh + 
				"\n\tmax results: " + queryNearest.max + 
				"\n\tfunction count: " + functions.size();
		// @formatter:on
	}
}
