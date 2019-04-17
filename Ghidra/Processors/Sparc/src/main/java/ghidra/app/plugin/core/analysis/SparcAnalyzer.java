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

import ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd;
import ghidra.app.services.AnalysisPriority;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Analyze Sparc binaries for certain patterns of instructions.
 *
 */

public class SparcAnalyzer extends ConstantPropagationAnalyzer {

	private final static String PROCESSOR_NAME = "Sparc";

	public SparcAnalyzer() {
		super(PROCESSOR_NAME);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));
	}

	@Override
	public AddressSetView flowConstants(final Program program, Address flowStart, AddressSetView flowSet, final SymbolicPropogator symEval, final TaskMonitor monitor)
			throws CancelledException {
		
		// get the function body
		Function func = program.getFunctionManager().getFunctionContaining(flowStart);
		if (func != null) {
			flowSet = func.getBody();
			flowStart = func.getEntryPoint();

			Instruction instr = program.getListing().getInstructionAt(flowStart);
			// special case for leaf PIC call
			if (instr.getMnemonicString().equals("retl")) {
				Instruction dInstr =
					program.getListing().getInstructionAfter(instr.getMinAddress());
				if (dInstr.getMnemonicString().equals("_add")) {
					Register r0 = dInstr.getRegister(0);
					Register r1 = dInstr.getRegister(1);
					Register r2 = dInstr.getRegister(2);
					// add some register to the o7 register.  This is just getting offset of current location
					if (r0 != null && r0.getName().equals("o7") && r1 != null && r1.equals(r2)) {
						func.setInline(true);
					}
				}
			}
		}

		// follow all flows building up context
		// use context to fill out addresses on certain instructions 
		ContextEvaluator eval = new ConstantPropagationContextEvaluator(trustWriteMemOption) {

			@Override
			public boolean evaluateContext(VarnodeContext context, Instruction instr) {
				FlowType ftype = instr.getFlowType();
				// Check for a call with a restore in the delay slot
				//    Then it is a non-returning call (share the called function return
				if (ftype.isCall()) {
					Address fallAddr = instr.getFallThrough();
					if (fallAddr == null) {
						return false;
					}
					Instruction delayInstr =
						instr.getProgram().getListing().getInstructionAfter(instr.getMaxAddress());
					if (delayInstr == null) {
						return false;
					}
					if (delayInstr.getMnemonicString().compareToIgnoreCase("_restore") == 0) {
						instr.setFallThrough(null);
						Instruction fallInstr =
							instr.getProgram().getListing().getInstructionAt(fallAddr);
						if (fallInstr == null) {
							return false;
						}
						if (fallInstr.getReferenceIteratorTo().hasNext()) {
							return false;
						}
						ClearFlowAndRepairCmd cmd =
							new ClearFlowAndRepairCmd(fallAddr, false, false, true);
						cmd.applyTo(instr.getProgram(), monitor);
					}
				}
				return false;
			}

			@Override
			public boolean evaluateDestination(VarnodeContext context, Instruction instruction) {
				FlowType flowType = instruction.getFlowType();
				if (!flowType.isJump()) {
					return false;
				}
				// TODO: if this is a switch stmt, add to destSet
				Reference[] refs = instruction.getReferencesFrom();
				if (refs.length <= 0 ||
					(refs.length == 1 && refs[0].getReferenceType().isData())) {
					destSet.addRange(instruction.getMinAddress(), instruction.getMinAddress());
				}
				return false;
			}
		};

		AddressSet resultSet = symEval.flowConstants(flowStart, flowSet, eval, true, monitor);

		return resultSet;
	}
}
