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
package ghidra.app.plugin.core.analysis.validator;

import docking.widgets.conditiontestpanel.ConditionResult;
import docking.widgets.conditiontestpanel.ConditionStatus;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.TaskMonitor;

public class OffcutReferencesValidator extends PostAnalysisValidator {
	private static final String NAME = "Offcut References Validator";
	private static final int MAX_OFFCUTS_TO_REPORT = 100;

	public OffcutReferencesValidator(Program program) {
		super(program);
	}

	@Override
	public ConditionResult doRun(TaskMonitor monitor) {
		StringBuilder warnings = new StringBuilder();
		if (PseudoDisassembler.hasLowBitCodeModeInAddrValues(program)) {
			return new ConditionResult(ConditionStatus.Skipped,
				"Language supports offcut references to function entry points");
		}
		int references = checkOffcutReferences(program, warnings, monitor);
		return new ConditionResult(
			references > 0 ? ConditionStatus.Warning : ConditionStatus.Passed, warnings.toString());
	}

	private int checkOffcutReferences(Program prog, StringBuilder messages, TaskMonitor monitor) {
		Listing listing = prog.getListing();
		AddressSetView executeSet = prog.getMemory().getExecuteSet();
		ReferenceManager refManager = prog.getReferenceManager();
		AddressIterator refIter = refManager.getReferenceDestinationIterator(executeSet, true);
		int offcutRefCount = 0;
		monitor.setIndeterminate(true);
		while (refIter.hasNext() && !monitor.isCancelled()) {
			monitor.incrementProgress(1);
			Address toAddr = refIter.next();
			if (toAddr.isMemoryAddress()) {
				Instruction instruction = listing.getInstructionContaining(toAddr);
				if (instruction != null) {
					Address instAddr = instruction.getAddress();
					if (!toAddr.equals(instAddr)) {
						offcutRefCount++;
						if (offcutRefCount < MAX_OFFCUTS_TO_REPORT) {
							messages.append("&nbsp;&nbsp;&nbsp;&nbsp;" + toAddr + "\n");
						}
						else if (offcutRefCount == MAX_OFFCUTS_TO_REPORT) {
							messages.append(
								"&nbsp;&nbsp;&nbsp;&nbsp;[Too many offcut references to list...]\n");
						}
					}
				}
			}

		}
		if (offcutRefCount > 0) {
			messages.insert(0, prog.getDomainFile().getName() + " has " + offcutRefCount +
				" offcut code reference(s):\n");
		}
		return offcutRefCount;
	}

	@Override
	public String getDescription() {
		return "Search for any offcut code references in the program";
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public String toString() {
		return getName();
	}
}
