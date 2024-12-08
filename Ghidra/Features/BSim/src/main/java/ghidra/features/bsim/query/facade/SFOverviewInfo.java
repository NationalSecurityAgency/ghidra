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

import java.util.Set;

import ghidra.features.bsim.query.protocol.PreFilter;
import ghidra.features.bsim.query.protocol.QueryNearestVector;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.listing.Program;

public class SFOverviewInfo {

	public static final int DEFAULT_QUERIES_PER_STAGE  = 10;		// Default number of separate function queries to make at one time
	
	private Set<FunctionSymbol> functions;
	private Program program;
	private QueryNearestVector queryNearestVector;
	private PreFilter preFilter;
	
	/**
	 * Constructs an overview request with default parameters.
	 * @param functions required--a set of functions (at least one) for which an overview will be 
	 * 					computed.  All functions must be from the same program.
	 * @throws IllegalArgumentException if <tt>functions</tt> is <tt>null</tt>/empty or functions
	 * are from multiple programs.  
	 */
	public SFOverviewInfo(Set<FunctionSymbol> functions) {
		if (functions == null)
			throw new IllegalArgumentException("Function list cannot be null");
		if (functions.isEmpty())
			throw new IllegalArgumentException("Function list cannot be empty");
		
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
		queryNearestVector = new QueryNearestVector();
		preFilter = new PreFilter();
	}
	
	/**
	 * @return the program from which all queried functions are from
	 */
	public Program getProgram() {
		return program;
	}

	public double getSimilarityThreshold() {
		return queryNearestVector.thresh;
	}
	
	public void setSimilarityThreshold(double similarityThreshold) {
		queryNearestVector.thresh = similarityThreshold;
	}
	
	public double getSignificanceThreshold() {
		return queryNearestVector.signifthresh;
	}
	
	public void setSignificanceThreshold(double significanceThreshold) {
		queryNearestVector.signifthresh = significanceThreshold;
	}
	
	public int getVectorMax() {
		return queryNearestVector.vectormax;
	}
	
	public void setVectorMax(int max) {
		queryNearestVector.vectormax = max;
	}
	
	public QueryNearestVector buildQueryNearestVector() {
		return queryNearestVector;
	}
	
	public Set<FunctionSymbol> getFunctions() {
		return functions;
	}
	
	public int getNumberOfStages(int queries_per_stage) {
		if ((functions == null)||(functions.size() == 0))
			return 1;
		if (queries_per_stage == 0)
			queries_per_stage = DEFAULT_QUERIES_PER_STAGE;
		return (functions.size() + (queries_per_stage-1)) / queries_per_stage;
	}
	
	public PreFilter getPreFilter(){
		return preFilter;
	}
}
