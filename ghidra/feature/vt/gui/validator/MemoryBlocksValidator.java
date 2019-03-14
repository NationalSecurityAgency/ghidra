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
package ghidra.feature.vt.gui.validator;

import ghidra.feature.vt.api.main.VTSession;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;
import docking.widgets.conditiontestpanel.ConditionResult;
import docking.widgets.conditiontestpanel.ConditionStatus;

public class MemoryBlocksValidator extends VTPreconditionValidator {
	private static final String NAME = "Memory Blocks Validator";

	public MemoryBlocksValidator(Program sourceProgram, Program destinationProgram,
			VTSession existingResults) {
		super(sourceProgram, destinationProgram, existingResults);
	}

	@Override
	public ConditionResult doRun(TaskMonitor monitor) {
		ConditionStatus status = ConditionStatus.Passed;
		StringBuilder warnings = new StringBuilder();

		String sourceProgName = sourceProgram.getDomainFile().getName();
		String destProgName = destinationProgram.getDomainFile().getName();

		MemoryBlock[] sourceBlocks = sourceProgram.getMemory().getBlocks();
		MemoryBlock[] destBlocks = destinationProgram.getMemory().getBlocks();

		int sourceNumBlocks = sourceBlocks.length;
		int destNumBlocks = destBlocks.length;

		int numBlocksToCompare = 0;
		int numBlocksNeededForPerfectMatch = 0;

		if (sourceNumBlocks >= destNumBlocks) {
			numBlocksToCompare = destNumBlocks;
			numBlocksNeededForPerfectMatch = sourceNumBlocks;
		}
		else {
			numBlocksToCompare = sourceNumBlocks;
			numBlocksNeededForPerfectMatch = destNumBlocks;
		}

		int numMatches = 0;
		int numMatchingNames = 0;

		monitor.setIndeterminate(false);
		monitor.initialize(numBlocksToCompare);
		for (int i = 0; i < numBlocksToCompare; i++) {
			monitor.setProgress(i);
			final String blockName = destBlocks[i].getName();
			MemoryBlock matchingABlock =
				sourceProgram.getMemory().getBlock(destBlocks[i].getName());
			if (matchingABlock != null) {
				numMatchingNames++;
				int sourcePerm = matchingABlock.getPermissions();
				if (sourcePerm == destBlocks[i].getPermissions()) {
					numMatches++;
				}
				else {
					warnings.append("Block " + destProgName + ":" + blockName +
						" doesn't match permissions of " + sourceProgName + ":" + blockName + "\n");
					status = ConditionStatus.Warning;
				}
			}
			else {
				warnings.append("Block " + destProgName + ":" + blockName + " doesn't appear in " +
					sourceProgName + "\n");
				status = ConditionStatus.Warning;
			}
		}
		if (numMatches != numBlocksNeededForPerfectMatch) {
			status = ConditionStatus.Warning;
			if (numMatches == numBlocksToCompare) {
				if (sourceNumBlocks > numMatches) {
					int addl = sourceNumBlocks - numMatches;
					String plural = addl > 1 ? "s" : "";
					warnings.append(sourceProgName + " has " + addl + " more block" + plural +
						" than " + destProgName + " (but the rest match)\n");
				}
				else if (destNumBlocks > numMatches) {
					int addl = destNumBlocks - numMatches;
					String plural = addl > 1 ? "s" : "";
					warnings.append(destProgName + " has " + addl + " more block" + plural +
						" than " + sourceProgName + " (but the rest match)\n");
				}
			}
			if (numMatchingNames == numBlocksNeededForPerfectMatch) {
				warnings.append("\nSUMMARY: Number and names of blocks match but not all permissions match.");
			}
			else {
				warnings.append("\nSUMMARY: Number, names, and permissions of blocks do not all match");
			}
		}
		return new ConditionResult(status, warnings.toString());
	}

	@Override
	public String getDescription() {
		return "Make sure the memory blocks in both programs match up.";
	}

	@Override
	public String getName() {
		return NAME;
	}
}
