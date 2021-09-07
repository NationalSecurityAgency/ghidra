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
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SH4EarlyAddressAnalyzer extends SH4AddressAnalyzer {

	/**
	 * The early SH4 address analyzer runs right after disassembly to lay down
	 * any dynamic call or jump references and to install the R12 value which
	 * is use for PIC calculations.
	 * Other calculated references will occur when the functions are better
	 * formed to stop mistakes in functions that flow together incorrectly.
	 */
	public SH4EarlyAddressAnalyzer() {
		super();
		this.setPriority(AnalysisPriority.DISASSEMBLY);
	}

	@Override
	public AddressSetView flowConstants(final Program program, Address flowStart,
			AddressSetView flowSet, final SymbolicPropogator symEval, final TaskMonitor monitor)
			throws CancelledException {

		// follow all flows building up context
		// use context to fill out addresses on certain instructions
		ContextEvaluator eval = new ConstantPropagationContextEvaluator(trustWriteMemOption) {

			@Override
			public boolean evaluateReference(VarnodeContext context, Instruction instr, int pcodeop,
					Address address, int size, RefType refType) {

				// if this is a call, some processors use the register value
				// used in the call for PIC calculations
				if (refType.isFlow()) {
					// set the called function to have a constant value for this register
					// WARNING: This might not always be the case, if called directly or with a different register
					//          But then it won't matter, because the function won't depend on the registers value.
					if (instr.getFlowType().isCall()) {
						propagateR12ToCall(program, context, address);
					}

					if (refType.isComputed()) {
						boolean doRef = super.evaluateReference(context, instr, pcodeop, address,
							size, refType);
						if (!doRef) {
							return false;
						}
						if (checkComputedRelativeBranch(program, monitor, instr, address, refType,
							pcodeop)) {
							return false;
						}
						return doRef;
					}
				}

				// in the Early analyzer, don't lay down anything other than computed call references
				return false;
			}
		};

		AddressSet resultSet = symEval.flowConstants(flowStart, null, eval, true, monitor);

		return resultSet;
	}
}
