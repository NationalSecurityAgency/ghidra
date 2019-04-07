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

import java.math.BigInteger;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class X86Analyzer extends ConstantPropagationAnalyzer {

	private final static String PROCESSOR_NAME = "x86";

	public X86Analyzer() {
		super(PROCESSOR_NAME);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));
	}

	@Override
	public AddressSetView flowConstants(final Program program, Address flowStart, AddressSetView flowSet, final SymbolicPropogator symEval, final TaskMonitor monitor)
			throws CancelledException {
		
		// follow all flows building up context
		// use context to fill out addresses on certain instructions 
		ContextEvaluator eval = new ConstantPropagationContextEvaluator(trustWriteMemOption) {
			
			@Override
			public boolean evaluateContext(VarnodeContext context, Instruction instr) {
				String mnemonic = instr.getMnemonicString();
				if (mnemonic.equals("LEA")) {
					Register reg = instr.getRegister(0);
					if (reg != null) {
						BigInteger val = context.getValue(reg, false);
						if (val != null) {
							long lval = val.longValue();
							Address refAddr = instr.getMinAddress().getNewAddress(lval);
							if ((lval > 4096 || lval < 0) && program.getMemory().contains(refAddr)) {
								if (instr.getOperandReferences(1).length == 0) {
									instr.addOperandReference(1, refAddr, RefType.DATA,
										SourceType.ANALYSIS);
								}
							}
						}
					}
				}
				return false;
			}

			@Override
			public boolean evaluateReference(VarnodeContext context, Instruction instr, int pcodeop,
					Address address, int size, RefType refType) {

				// don't allow flow references to locations not in memory if the location is not external.
				if (refType.isFlow() && !instr.getMemory().contains(address) &&
					!address.isExternalAddress()) {
					return false;
				}

				return super.evaluateReference(context, instr, pcodeop, address, size, refType);
			}
		};

		AddressSet resultSet = symEval.flowConstants(flowStart, flowSet, eval, true, monitor);

		return resultSet;
	}
}
