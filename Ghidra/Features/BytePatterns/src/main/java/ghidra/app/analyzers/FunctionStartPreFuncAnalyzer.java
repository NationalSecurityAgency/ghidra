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
package ghidra.app.analyzers;

import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.util.constraint.ProgramDecisionTree;

public class FunctionStartPreFuncAnalyzer extends FunctionStartAnalyzer {

	protected static final String FUNCTION_START_PRE_SEARCH = "Function Start Pre Search";
	
	private static final String DESCRIPTION =
			"Search for architecture/compiler specific patterns that are better found before any code is disassembled, " +
			"such as known patterns for ARM functions that handle switch tables and don't return.";
	
	private static ProgramDecisionTree prePatternDecisitionTree;
	
	private static ProgramDecisionTree initializePatternDecisionTree() {
		if (prePatternDecisitionTree == null) {
			prePatternDecisitionTree = Patterns.getPatternDecisionTree("prepatternconstraints.xml");
		}
		return prePatternDecisitionTree;
	}
	
	@Override
	public ProgramDecisionTree getPatternDecisionTree() {
		return initializePatternDecisionTree();
	}

	public FunctionStartPreFuncAnalyzer() {
		super(FUNCTION_START_PRE_SEARCH, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		
		setPriority(AnalysisPriority.BLOCK_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}
}
