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
package ghidra.app.plugin.core.analysis;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class SegmentedCallingConventionAnalyzer extends AbstractAnalyzer {
	private final static String NAME = "Segmented X86 Calling Conventions";
	private static final String DESCRIPTION =
		"Analyzes X86 programs with segmented address spaces to identify a calling convention for each function.  This analyzer looks at the type of return used for the function to identify the calling convention.";

	public SegmentedCallingConventionAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getMinAddress() instanceof SegmentedAddress &&
			program.getLanguage().supportsPcode();
	}

	void checkReturn(Program program, Instruction instr) {
		String mnemonic = instr.getMnemonicString().toLowerCase();
		if (mnemonic.startsWith("ret")) {
			String convention = null;
			//Scalar purge = instr.getScalar(0);
			int b = 0;
			try {
				b = program.getMemory().getByte(instr.getMinAddress()) & 0xff;
			}
			catch (MemoryAccessException e) {
				return;
			}
			switch (b) {
				case 0xca:
					convention = "__stdcall16far";
					break;
				case 0xcb:
					convention = "__cdecl16far";
					break;
				case 0xc3:
					convention = "__cdecl16near";
					break;
				case 0xc2:
					convention = "__stdcall16near";
					break;
			}
			if (convention != null) {
				Function func =
					program.getFunctionManager().getFunctionContaining(instr.getMinAddress());
				if (func != null) {
					try {
						func.setCallingConvention(convention);
					}
					catch (InvalidInputException e) {
						Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
					}
				}
			}
			return;
		}
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		InstructionIterator instructions = program.getListing().getInstructions(set, true);
		while (instructions.hasNext()) {
			Instruction next = instructions.next();
			checkReturn(program, next);
		}
		return true;
	}

}
