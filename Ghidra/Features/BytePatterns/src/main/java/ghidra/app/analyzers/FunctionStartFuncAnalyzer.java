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
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.bytesearch.SequenceSearchState;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class FunctionStartFuncAnalyzer extends FunctionStartAnalyzer {
	protected static final String FUNCTION_START_POST_SEARCH = "Function Start Post Search";

	public FunctionStartFuncAnalyzer() {
		super(NAME, AnalyzerType.FUNCTION_ANALYZER);
		setSupportsOneTimeAnalysis(false);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.before().before());
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		// check that the check function later property has been set at the functions start
		//    before passing the cut down address set to the real search algorithm to to the correct action
		AddressSet potentialPreMatches =
			getOrCreatePotentialMatchPropertyMap(program).getAddressSet();
		set = set.intersect(potentialPreMatches);

		// no previous no-function existing pre-requisites to check
		if (set.isEmpty()) {
			return true;
		}
		
		return super.added(program, set, monitor, log);
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
		if (hasFunctionStartConstraints) {
			// cache the localRoot
			rootState = localRoot;
			return true;
		}
		return false;
	}
}
