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
package ghidra.app.plugin.core.function;

import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SharedReturnJumpAnalyzer extends SharedReturnAnalyzer {
	// note same name as parent, so that it only shows up once in the analysis options
	private static final String NAME = "Shared Return Calls";

	private final static int NOTIFICATION_INTERVAL = 4096;

	public SharedReturnJumpAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.CODE_ANALYSIS.before().before());
		setSupportsOneTimeAnalysis(false);
	}

	/**
	 * Called when code has been added.
	 * Looks instructions for jumps to functions that are shared returns.
	 * @throws CancelledException
	 */
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		ReferenceManager mgr = program.getReferenceManager();
		Listing listing = program.getListing();

		AddressSet sharedReturnSet = new AddressSet();

		int count = 0;
		long initial_count = set.getNumAddresses();
		monitor.initialize(initial_count);
		AddressSet leftSet = new AddressSet(set);

		//
		// gather up all the locations that are referenced as calls
		//
		AddressIterator iter = mgr.getReferenceSourceIterator(set, true);
		while (iter.hasNext()) {
			monitor.checkCanceled();

			Address addr = iter.next();

			count++;
			if (count > NOTIFICATION_INTERVAL) {
				leftSet.deleteRange(leftSet.getMinAddress(), addr);
				monitor.setProgress(initial_count - leftSet.getNumAddresses());
				monitor.setMessage("Find Shared Return : " + addr);
				count = 0;
			}

			Instruction instr = listing.getInstructionAt(addr);
			if (instr == null) {
				continue;
			}
			FlowType flowType = instr.getFlowType();
			if (!flowType.isJump()) {
				continue;
			}
			Reference[] refs = mgr.getFlowReferencesFrom(addr);

			for (int refIndex = 0; refIndex < refs.length; refIndex++) {
				Reference ref = refs[refIndex];
				RefType refType = ref.getReferenceType();

				if (refType.isJump()) {
					// check if the refto is a function
					// throw it on the jump to function list
					Address entryAddr = ref.getToAddress();

					Function funcAt = program.getFunctionManager().getFunctionAt(entryAddr);
					if (funcAt == null) {
						continue;
					}

					sharedReturnSet.addRange(entryAddr, entryAddr);
				}
			}
		}

		return super.added(program, sharedReturnSet, monitor, log);
	}

}
