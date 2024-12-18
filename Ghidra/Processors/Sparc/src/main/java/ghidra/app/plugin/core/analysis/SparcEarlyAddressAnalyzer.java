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
package ghidra.app.plugin.core.analysis;

import ghidra.app.services.AnalysisPriority;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Analyze all call instructions with a delay slot to see if the o7 register is changed to something other than
 * the normal return address after the call instruction.
 * 
 * Note: This extends the SparcAnalyzer to use the same Analyzer name, this doesn't do constant analysis.
 */
public class SparcEarlyAddressAnalyzer extends SparcAnalyzer {

	/**
	 * The early Sparc analyzer catches instructions with sets of the o7 link
	 * address register to a value other than right after the function
	 */
	public SparcEarlyAddressAnalyzer() {
		super();
		// analysis should happen right after disassembly
		this.setPriority(AnalysisPriority.DISASSEMBLY);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		if (!o7CallReturnAnalysis) {
			return true;
		}
		
		AddressSet unanalyzedSet = new AddressSet(set);
		
		Register linkReg = program.getLanguage().getRegister("o7");
		
		InstructionIterator instructions = program.getListing().getInstructions(unanalyzedSet, true);
		for (Instruction instr : instructions) {
			if (!instr.getFlowType().isCall()) {
				continue;
			}
			if (!instr.hasFallthrough()) {
				continue;
			}
			
			PcodeOp[] pcode = instr.getPcode();
			for (PcodeOp pcodeOp : pcode) {
				Varnode output = pcodeOp.getOutput();
				if (output == null || !output.getAddress().equals(linkReg.getAddress())) {
					continue;
				}
				Varnode input = pcodeOp.getInput(0);
				if (input.isConstant()) {
					continue; // this is just assigning the return value after the call
				}
				//instr.setFallThrough(null);
				instr.setFlowOverride(FlowOverride.CALL_RETURN);
				break;
			}
		}

		return true;
	}
}
