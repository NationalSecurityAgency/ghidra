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
package wasm.analysis;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.LEB128;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class WasmPreAnalyzer extends AbstractAnalyzer {
	private final static String NAME = "Wasm Pre-Analyzer";
	private final static String DESCRIPTION = "Analyze Wasm code before disassembly to resolve operand sizes and jump offsets";

	private final static int CSTACK_GLOBAL_DISABLE = -1;
	private final static int CSTACK_GLOBAL_AUTO = -2;

	private final static String OPTION_NAME_CSTACK_GLOBAL = "C Stack Pointer";
	private static final String OPTION_DESCRIPTION_CSTACK_GLOBAL = "0-based index of the global variable being used as the C stack pointer. Set to -1 to disable C stack inference. Set to -2 to guess C stack pointer automatically (default).";
	private final static int OPTION_DEFAULT_CSTACK_GLOBAL = CSTACK_GLOBAL_AUTO;
	private int cStackGlobal = OPTION_DEFAULT_CSTACK_GLOBAL;

	public WasmPreAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		// run immediately before initial disassembly
		setPriority(AnalysisPriority.BLOCK_ANALYSIS.before());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(Processor.findOrPossiblyCreateProcessor("WebAssembly"));
	}

	@Override
	public void registerOptions(Options options, Program program) {
		HelpLocation helpLocation = new HelpLocation("AutoAnalysisPlugin", "Auto_Analysis_Option_Instructions");

		options.registerOption(OPTION_NAME_CSTACK_GLOBAL, cStackGlobal, helpLocation,
				OPTION_DESCRIPTION_CSTACK_GLOBAL);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		cStackGlobal = options.getInt(OPTION_NAME_CSTACK_GLOBAL, cStackGlobal);
	}

	private int guessCStackGlobalForFunction(Program program, Address funcAddress) throws IOException {
		BinaryReader codeReader = new BinaryReader(new MemoryByteProvider(program.getMemory(), funcAddress), true);
		int localsCount = codeReader.readNextVarInt(LEB128::signed);
		for (int i = 0; i < localsCount; i++) {
			codeReader.readNextVarInt(LEB128::signed); /* count */
			codeReader.readNextVarInt(LEB128::signed); /* type */
		}

		/*
		 * Look for a global.get at the start of the function, and assume that it loads
		 * the C stack pointer if present
		 */
		if (codeReader.readNextUnsignedByte() != 0x23)
			return -1;
		return codeReader.readNextVarInt(LEB128::signed);
	}

	private int guessCStackGlobal(Program program, List<WasmFuncSignature> functions, TaskMonitor monitor) {
		/* Guess the C stack global by looking at which global appears most often */
		Map<Integer, Integer> cStackGuesses = new HashMap<>();
		monitor.setMessage("Analyzing C stack...");
		monitor.initialize(functions.size());
		for (WasmFuncSignature function : functions) {
			if (monitor.isCancelled()) {
				return CSTACK_GLOBAL_AUTO;
			}
			monitor.incrementProgress(1);

			if (function.isImport()) {
				continue;
			}

			try {
				int guessedGlobal = guessCStackGlobalForFunction(program, function.getStartAddr());
				if (guessedGlobal != -1) {
					int count = cStackGuesses.getOrDefault(guessedGlobal, 0);
					cStackGuesses.put(guessedGlobal, count + 1);
				}
			} catch (IOException e) {
				Msg.error(this, "Failed to analyze function " + function.getName(), e);
			}
		}

		int bestGuess = CSTACK_GLOBAL_DISABLE;
		int bestCount = -1;
		for (Map.Entry<Integer, Integer> entry : cStackGuesses.entrySet()) {
			if (entry.getValue() > bestCount) {
				bestGuess = entry.getKey();
				bestCount = entry.getValue();
			}
		}
		Msg.info(this, "Guessed C stack global: " + bestGuess);
		return bestGuess;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
		monitor.setMessage("Parsing module...");
		WasmAnalysis state = WasmAnalysis.getState(program);
		List<WasmFuncSignature> functions = state.getFunctions();

		if (cStackGlobal == CSTACK_GLOBAL_AUTO) {
			cStackGlobal = guessCStackGlobal(program, functions, monitor);
		}

		monitor.setMessage("Analyzing functions...");
		monitor.initialize(functions.size());

		Disassembler disassembler = Disassembler.getDisassembler(program, monitor, new DisassemblerMessageListener() {
			@Override
			public void disassembleMessageReported(String msg) {
				if (monitor != null) {
					monitor.setMessage(msg);
				}
			}
		});
		disassembler.setRepeatPatternLimit(-1);

		/*
		 * TODO: Support reanalyzing changed functions, to handle patches and
		 * significant function changes.
		 * TODO: Support reanalyzing to change C stack pointer
		 */
		for (Function function : program.getListing().getFunctions(set, true)) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.incrementProgress(1);

			WasmFunctionAnalysis funcAnalysis;
			try {
				funcAnalysis = state.getFunctionAnalysis(function.getEntryPoint());
			} catch (Exception e) {
				Msg.error(this, "Failed to analyze function " + function.getName() + " @ " + function.getEntryPoint(), e);
				function.setComment("WARNING: Wasm function analysis failed, output may be incorrect: " + e);
				continue;
			}
			if (funcAnalysis == null) {
				continue;
			}

			try {
				funcAnalysis.applyContext(program, cStackGlobal);
				AddressSet funcSet = new AddressSet(
					funcAnalysis.getSignature().getStartAddr(),
					funcAnalysis.getSignature().getEndAddr());
				disassembler.disassemble(funcSet, funcSet, false);
			} catch (Exception e) {
				Msg.error(this, "Failed to analyze function " + function.getName() + " @ " + function.getEntryPoint(), e);
			}
		}
		return true;
	}
}
