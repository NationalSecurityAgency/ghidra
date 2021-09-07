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

import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SH4AddressAnalyzer extends ConstantPropagationAnalyzer {

	private static final String OPTION_NAME_PROPAGATE_R12 = "Propagate constant R12";
	private static final String OPTION_DESCRIPTION_PROPAGATE_R12 =
		"R12 can be used as a pointer to the GOT table. If it is a constant value propagate the value into called functions.";

	private static final boolean OPTION_DEFAULT_PROPAGATE_R12 = true;

	protected boolean propagateR12 = OPTION_DEFAULT_PROPAGATE_R12;

	protected Register r12;

	private final static String PROCESSOR_NAME = "SuperH4";

	public SH4AddressAnalyzer() {
		super(PROCESSOR_NAME);
	}

	@Override
	public boolean canAnalyze(Program program) {
		boolean canAnalyze = program.getLanguage()
				.getProcessor()
				.equals(Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));

		if (!canAnalyze) {
			return false;
		}

		r12 = program.getRegister("r12");

		return true;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		return super.added(program, set, monitor, log);
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
				if (refType.isCall()) {
					// set the called function to have a constant value for this register
					// WARNING: This might not always be the case, if called directly or with a different register
					//          But then it won't matter, because the function won't depend on the registers value.
					if (instr.getFlowType().isCall()) {
						propagateR12ToCall(program, context, address);
					}
				}

				boolean doRef =
					super.evaluateReference(context, instr, pcodeop, address, size, refType);
				if (!doRef) {
					return false;
				}
				if (checkComputedRelativeBranch(program, monitor, instr, address, refType,
					pcodeop)) {
					return false;
				}
				return doRef;
			}
		};

		AddressSet resultSet = symEval.flowConstants(flowStart, null, eval, true, monitor);

		return resultSet;
	}

	/**
	 * Check if this is a computed relative branch that needs the reference placed on the correct operand.
	 * 
	 * @param program program
	 * @param monitor task monitor
	 * @param instr instruction to add references to
	 * @param address target address
	 * @param refType type of reference
	 * @param pcodeop pcode operation causing the reference
	 * @return true if the reference was handled in this routine
	 */
	protected boolean checkComputedRelativeBranch(final Program program, final TaskMonitor monitor,
			Instruction instr, Address address, RefType refType, int pcodeop) {
		// unimplemented is a flag for a parameter check
		if (pcodeop == PcodeOp.UNIMPLEMENTED) {
			return false;
		}
		// non-computed don't need to place the reference
		if (!refType.isComputed()) {
			return false;
		}

		// force the reference on the first operand for bsrf
		String mnemonic = instr.getMnemonicString();
		if (mnemonic.equals("bsrf") || mnemonic.equals("braf")) {
			instr.addOperandReference(0, address, refType, SourceType.ANALYSIS);

			// need to handle disassembly too
			Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
			AddressSet disassembleAddrs = dis.disassemble(address, null);
			AutoAnalysisManager.getAnalysisManager(program).codeDefined(disassembleAddrs);
			return true;
		}
		return false;
	}

	protected void propagateR12ToCall(Program program, VarnodeContext context, Address address) {
		if (!propagateR12) {
			return;
		}

		RegisterValue registerValue = context.getRegisterValue(r12);
		if (registerValue != null) {
			BigInteger value = registerValue.getUnsignedValue();
			ProgramContext progContext = program.getProgramContext();
			try {
				progContext.setValue(r12, address, address, value);
			}
			catch (ContextChangeException e) {
				// ignore
			}
		}
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		super.optionsChanged(options, program);

		options.registerOption(OPTION_NAME_PROPAGATE_R12, OPTION_DEFAULT_PROPAGATE_R12, null,
			OPTION_DESCRIPTION_PROPAGATE_R12);

		propagateR12 = options.getBoolean(OPTION_NAME_PROPAGATE_R12, OPTION_DEFAULT_PROPAGATE_R12);
	}
}
