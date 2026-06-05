/* ###
 * IP: GHIDRA
 * NOTE: Need to review if these patterns are any indicators of code/original binary, even the address examples
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

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.IncompatibleMaskException;
import ghidra.program.model.lang.MaskImpl;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class HexagonPrologEpilogAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Hexagon Prolog/Epilog Functions";
	private static final String DESCRIPTION =
		"Detects common Prolog/Epilog functions used within Hexagon code and marks them as inline";

	private final static String PROCESSOR_NAME = "Hexagon";

	private final static String OPTION_NAME_FIXUP_FUNCTIONS = "Prolog/Epilog Function Fixup";

	private static final String OPTION_DESCRIPTION_FIXUP_FUNCTIONS =
		"Select fixup type which should be applied to Prolog functions (save registers) and Epilog functions (restore registers and dealloc frame).";

	public enum FIXUP_TYPES {
		Name_Only, Inline, Call_Fixup
	}

	private FIXUP_TYPES fixupType = FIXUP_TYPES.Call_Fixup;

	// Call fixup names as defined in cspec
	private final static String CALL_FIXUP_PROLOG_NAME = "prolog_save_regs";
	private final static String CALL_FIXUP_EPILOG_NAME = "prolog_restore_regs";

	// TODO: These patterns may be incomplete
	private static InstructionMaskValue NOP = new InstructionMaskValue(0xffff3fff, 0x7f000000); // nop - ignore parse bits
	private static InstructionMaskValue JUMPR_LR = new InstructionMaskValue(0xffff3fff, 0x529f0000); // jumpr lr - ignore parse bits
	private static InstructionMaskValue JUMP = new InstructionMaskValue(0xfe000001, 0x58000000); // jump - ignore parse bits
	private static InstructionMaskValue MEMD_PUSH =
		new InstructionMaskValue(0xfdff0000, 0xa5de0000); // memd (FP+#-nn),<rtt5> - ignore parse bits
	private static InstructionMaskValue MEMD_POP = new InstructionMaskValue(0xfdff0000, 0x95de0000); // memd <rdd5>,(FP+#-nn) - ignore parse bits
	private static InstructionMaskValue DEALLOCFRAME = new InstructionMaskValue(0xffff3fff,
		0x901e001e); // deallocframe - ignore parse bits
	private static InstructionMaskValue DEALLOC_RETURN = new InstructionMaskValue(0xffff3fff,
		0x961e001e); // deallocreturn - ignore parse bits

	public HexagonPrologEpilogAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.CODE_ANALYSIS.before());
	}

	@Override
	public boolean canAnalyze(Program program) {
		if (!PROCESSOR_NAME.equals(program.getLanguage().getProcessor().toString())) {
			return false;
		}
		return true;
	}

	private boolean setPrologEpilog(Program program, Address entryPoint, boolean isProlog,
			TaskMonitor monitor) {
		Listing listing = program.getListing();
		Function function = listing.getFunctionAt(entryPoint);
		if (function == null) {
			CreateFunctionCmd cmd = new CreateFunctionCmd(entryPoint);
			if (!cmd.applyTo(program, monitor)) {
				return false;
			}
			function = cmd.getFunction();
		}
		else if (function.isInline()) {
			return true;
		}
		setPrologEpilog(function, isProlog);
		return true;
	}

	private void setPrologEpilog(Function function, boolean isProlog) {

		if (fixupType == FIXUP_TYPES.Inline) {
			function.setInline(true);
			Msg.info(this, "Set inline " + (isProlog ? "prolog" : "epilog") + " function at " +
				function.getEntryPoint());
		}
		else if (fixupType == FIXUP_TYPES.Call_Fixup) {
			function.setCallFixup(isProlog ? CALL_FIXUP_PROLOG_NAME : CALL_FIXUP_EPILOG_NAME);
			Msg.info(this, "Set call-fixup " + (isProlog ? "prolog" : "epilog") + " function at " +
				function.getEntryPoint());
		}

		if (function.getSymbol().getSource() == SourceType.DEFAULT) {
			String name = isProlog ? "prolog_save_regs@" : "epilog_restore_regs@";
			try {
				function.setName(name + function.getEntryPoint(), SourceType.ANALYSIS);
			}
			catch (DuplicateNameException e) {
				// ignore
			}
			catch (InvalidInputException e) {
				throw new AssertException(e);
			}
		}
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		monitor.setMessage("Find Prologs and Epilogs...");
		monitor.initialize(set.getNumAddresses());

		int cnt = 0;
		for (Function function : program.getListing().getFunctions(set, true)) {
			monitor.checkCancelled();
			monitor.setProgress(++cnt);
			if (function.isInline() || function.getCallFixup() != null) {
				continue;
			}
			if (isProlog(program, function.getEntryPoint(), true, monitor)) {
				setPrologEpilog(function, true);
			}
			else if (isEpilog(program, function.getEntryPoint(), true, monitor)) {
				setPrologEpilog(function, false);
			}
		}

		return true;
	}

	private boolean isProlog(Program program, Address entryPoint, boolean recurseOk,
			TaskMonitor monitor) throws CancelledException {
		DumbMemBufferImpl mem = new DumbMemBufferImpl(program.getMemory(), entryPoint);
		int memdCnt = 0;
		boolean returnPending = false;
		byte[] bytes = new byte[4];
		for (int i = 0; i < 5; i++) {
			if (mem.getBytes(bytes, i * 4) != 4) {
				return false;
			}
			if (NOP.isMatch(bytes)) {
				// ignore
			}
			else if (JUMPR_LR.isMatch(bytes)) {
				returnPending = true;
			}
			else if (JUMP.isMatch(bytes)) {
				if (!recurseOk ||
					!hasContinuationFunction(program, entryPoint.add(i * 4), true, monitor)) {
					return false;
				}
				returnPending = true;
			}
			else if (MEMD_PUSH.isMatch(bytes)) {
				++memdCnt;
			}
			else {
				return false; // unexpected instruction for prolog
			}
			if (returnPending && ((bytes[1] & 0x0c0) == 0x0c0)) {
				break; // return pending and at end of parallel group
			}
		}
		return (memdCnt != 0);
	}

	private boolean isEpilog(Program program, Address entryPoint, boolean recurseOk,
			TaskMonitor monitor) throws CancelledException {
		DumbMemBufferImpl mem = new DumbMemBufferImpl(program.getMemory(), entryPoint);
		int memdCnt = 0;
		boolean returnPending = false;
		byte[] bytes = new byte[4];
		for (int i = 0; i < 5; i++) {
			if (mem.getBytes(bytes, i * 4) != 4) {
				return false;
			}
			if (NOP.isMatch(bytes)) {
				// ignore
			}
			else if (JUMPR_LR.isMatch(bytes) || DEALLOC_RETURN.isMatch(bytes)) {
				returnPending = true;
			}
			else if (JUMP.isMatch(bytes)) {
				if (!recurseOk ||
					!hasContinuationFunction(program, entryPoint.add(i * 4), false, monitor)) {
					return false;
				}
				returnPending = true;
			}
			else if (MEMD_POP.isMatch(bytes)) {
				++memdCnt;
			}
			else if (DEALLOCFRAME.isMatch(bytes)) {
				// ignore
			}
			else {
				return false; // unexpected instruction for prolog
			}
			if (returnPending && ((bytes[1] & 0x0c0) == 0x0c0)) {
				break; // return pending and at end of parallel group
			}
		}
		return (memdCnt != 0);
	}

	private boolean hasContinuationFunction(Program program, Address jumpFromAddr,
			boolean checkProlog, TaskMonitor monitor) throws CancelledException {
		Listing listing = program.getListing();
		Instruction instr = listing.getInstructionAt(jumpFromAddr);
		if (instr == null) {
			// unable to continue without instruction at jumpFromAddr
			return false;
		}
		Address destAddr = instr.getAddress(0);
		if (destAddr == null) {
			return false;
		}
		if (checkProlog) {
			return (isProlog(program, destAddr, false, monitor) && setPrologEpilog(program,
				destAddr, true, monitor));
		}
		return (isEpilog(program, destAddr, false, monitor) && setPrologEpilog(program, destAddr,
			false, monitor));
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_NAME_FIXUP_FUNCTIONS, FIXUP_TYPES.Name_Only, null,
			OPTION_DESCRIPTION_FIXUP_FUNCTIONS);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		fixupType = options.getEnum(OPTION_NAME_FIXUP_FUNCTIONS, FIXUP_TYPES.Name_Only);
	}

	private static class InstructionMaskValue {

		private MaskImpl mask;
		private byte[] valueBytes;

		InstructionMaskValue(int maskValue, int value) {
			mask = new MaskImpl(getBytes(maskValue));
			valueBytes = getBytes(value);
		}

		public boolean isMatch(byte[] bytes) {
			try {
				return mask.equalMaskedValue(bytes, valueBytes);
			}
			catch (IncompatibleMaskException e) {
				throw new AssertException(e);
			}
		}
	}

	private static byte[] getBytes(int value) {
		byte[] bytes = new byte[4];
		// TODO: Order may need to change !!
		bytes[0] = (byte) value;
		bytes[1] = (byte) (value >> 8);
		bytes[2] = (byte) (value >> 16);
		bytes[3] = (byte) (value >> 24);
		return bytes;
	}

}
