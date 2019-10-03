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

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class HCS12ConventionAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "HCS12 Calling Convention";
	private static final String DESCRIPTION = "Analyzes HCS12 programs with paged memory access  to identify a calling convention for each function.  This analyzer looks at the type of return used for the function to identify the calling convention.";

	Register xgate = null;

	public HCS12ConventionAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS);
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		// Only analyze HCS12 Programs
		Processor processor = program.getLanguage().getProcessor();

		boolean canDo = processor.equals(Processor.findOrPossiblyCreateProcessor("HCS12"));
		if (canDo) {
			xgate = program.getRegister("XGATE");
		}

		return canDo;
	}

	void checkReturn(Program program, Instruction instr) {
		String mnemonic = instr.getMnemonicString().toLowerCase();

		if (instr == null || !instr.getFlowType().isTerminal()) {
			return;
		}

		// if XGATE set on instruction is XGATE
		RegisterValue xgateValue = program.getProgramContext().getRegisterValue(xgate, instr.getMinAddress());
		if (xgateValue != null && xgateValue.hasValue() && xgateValue.getUnsignedValue().equals(BigInteger.ONE)) {
			setPrototypeModel(program, instr, "__asm_xgate");
			return;
		}

		// set the correct convention
		if (mnemonic.equals("rtc")) {
			setPrototypeModel(program, instr, "__asmA_longcall");
			return;
		}

		if (mnemonic.equals("rts")) {
			setPrototypeModel(program, instr, "__asmA");
			return;
		}

	}

	private void setPrototypeModel(Program program, Instruction instr, String convention) {
		if (convention == null) {
			return;
		}

		Function func = program.getFunctionManager().getFunctionContaining(instr.getMinAddress());
		if (func == null) {
			return;
		}

		if (func.getSignatureSource() != SourceType.DEFAULT) {
			return;
		}

		try {
			func.setCallingConvention(convention);
		} catch (InvalidInputException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		// get all functions within the set
		FunctionIterator functions = program.getFunctionManager().getFunctions(set, true);
		for (Function function : functions) {

			// for each function body, search instructions
			AddressSetView body = function.getBody();
			InstructionIterator instructions = program.getListing().getInstructions(body, true);
			for (Instruction instr : instructions) {
				if (instr.getFlowType().isTerminal()) {
					checkReturn(program, instr);
				}
			}
		}
		return true;
	}

}
