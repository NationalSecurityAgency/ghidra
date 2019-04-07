/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
import ghidra.program.model.listing.Program;
import ghidra.util.bytesearch.SequenceSearchState;

public class FunctionStartPostAnalyzer extends FunctionStartAnalyzer {
	protected static final String FUNCTION_START_POST_SEARCH = "Function Start Post Search";

	public FunctionStartPostAnalyzer() {
		super(NAME + " After Code", AnalyzerType.INSTRUCTION_ANALYZER);
		setSupportsOneTimeAnalysis(false);
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.before().before());
	}

	@Override
	public boolean canAnalyze(Program program) {
		if (!super.canAnalyze(program)) {
			return false;
		}
		SequenceSearchState localRoot = initialize(program);
		if (localRoot == null) {
			return false;
		}
		if (hasCodeConstraints || hasDataConstraints) {
			// cache the localRoot
			rootState = localRoot;
			return true;
		}
		return false;
	}
}
