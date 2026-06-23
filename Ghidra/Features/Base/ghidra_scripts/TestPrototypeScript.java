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
// This script uses the emulator to test a prototype defined in a cspec file. It is intended to be 
// run on programs produced by compiling a source file produced by the script 
// GeneratePrototypeTestFileScript.java. The program must have the same name as the source file
// except without the .c suffix (e.g., program = test_file, source = test_file.c) and the two files
// must reside in the same directory.  The first time you run this file on a program, it will parse
// the c source file and apply the correct data types and function definitions.  If you run the 
// script without a selection it will test all test functions and print out which ones have
// errors.  If the script is run with a selection, it will print out detailed information about each 
// test function overlapping the selection (whether or not it has an error).
import java.util.*;
import java.util.function.Consumer;

import ghidra.app.script.GhidraScript;
import ghidra.pcode.emu.EmulatorUtilities;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.InterruptPcodeExecutionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.test.compilers.support.CSpecPrototypeTestUtil;
import ghidra.test.compilers.support.CSpecPrototypeTestUtil.TestResult;
import ghidra.test.compilers.support.CSpecTestPCodeEmulator;
import ghidra.util.DataConverter;

public class TestPrototypeScript extends GhidraScript {
	// Whether to print extra diagnostic information, such as the emulator's disassembly
	private static final boolean ENABLE_DEBUG_PRINTING = false;
	private static final int DEBUG_PRINTING_LEVEL = 3;

	private DataConverter dataConverter;
	private LanguageCompilerSpecPair langCompPair;
	private boolean manualSelection = false;
	private CSpecTestPCodeEmulator emulator;
	private Consumer<String> logger = (msg -> printf("  %s\n", msg));

	@Override
	protected void run() throws Exception {
		langCompPair = getLangCompPair(currentProgram);
		PrototypeModel model =
			CSpecPrototypeTestUtil.getProtoModelToTest(currentProgram, langCompPair);
		dataConverter = DataConverter.getInstance(langCompPair.getLanguage().isBigEndian());
		FunctionManager fManager = currentProgram.getFunctionManager();

		CSpecPrototypeTestUtil.applyInfoFromSourceIfNeeded(currentProgram, model);

		// Load program into emulator
		emulator =
			new CSpecTestPCodeEmulator(currentProgram.getLanguage(), !ENABLE_DEBUG_PRINTING,
				DEBUG_PRINTING_LEVEL, logger);
		EmulatorUtilities.loadProgram(emulator, currentProgram);

		Iterator<Function> fIter = currentSelection == null ? fManager.getFunctionsNoStubs(true)
				: fManager.getFunctionsOverlapping(currentSelection);
		manualSelection = currentSelection != null;

		List<Function> errors = new ArrayList<>();
		while (fIter.hasNext()) {
			Function caller = fIter.next();
			if (!(caller.getName().startsWith("params") || caller.getName().startsWith("return"))) {
				continue;
			}

			Function callee = CSpecPrototypeTestUtil.getFirstCall(caller);
			ArrayList<ParameterPieces> pieces =
				CSpecPrototypeTestUtil.getParameterPieces(caller, callee, model);
			Address breakpoint = null;
			if (caller.getName().startsWith("params")) {
				breakpoint = callee.getEntryPoint();
			}
			else {
				// find the address of the call to producer
				ReferenceIterator refIter =
					currentProgram.getReferenceManager().getReferencesTo(callee.getEntryPoint());
				if (!refIter.hasNext()) {
					throw new AssertionError(
						"no references to " + callee.getName() + " in " + caller.getName());
				}
				Reference ref = null;
				while (refIter.hasNext()) {
					Reference r = refIter.next();
					if (!r.getReferenceType().isCall()) {
						continue;
					}
					if (caller.getBody().contains(r.getFromAddress())) {
						ref = r;
						break;
					}
				}
				if (ref == null) {
					throw new AssertionError(
						"call to " + callee.getName() + " not found in " + caller.getName());
				}
				Instruction afterCall =
					currentProgram.getListing().getInstructionAfter(ref.getFromAddress());
				// For architectures with a delay slot, break on the actual aftercall instruction,
				// by stepping instructions until we are out of the delay slot.
				while (afterCall.isInDelaySlot()) {
					afterCall = afterCall.getNext();
				}
				breakpoint = afterCall.getAddress();

			}

			boolean error = testFunction(caller, callee, breakpoint, pieces);
			if (error) {
				errors.add(caller);
			}
		}

		if (errors.size() == 0) {
			printf("No prototype errors found.\n");
			return;
		}
		printf("%d prototype error(s) found:\n", errors.size());
		for (Function errFunc : errors) {
			printf("  %s\n", errFunc.getName());
		}
	}

	private boolean testFunction(Function caller, Function callee, Address breakPoint,
			ArrayList<ParameterPieces> pieces) throws Exception {

		List<byte[]> groundTruth =
			CSpecPrototypeTestUtil.getPassedValues(callee, pieces, dataConverter, logger);

		// breakpoint will be skipped if condition is false, so add condition that is always true
		emulator.addBreakpoint(breakPoint, "1:1");

		PcodeThread<byte[]> emuThread = emulator.prepareFunction(caller);

		Register stackReg = caller.getProgram().getCompilerSpec().getStackPointer();

		try {
			emuThread.run();
			printerr("Emulator should have hit breakpoint");
		}
		catch (InterruptPcodeExecutionException e) {
			// this is the breakpoint, which is what we want to happen
		}

		List<byte[]> fromEmulator = new ArrayList<>();
		for (ParameterPieces piece : pieces) {
			fromEmulator.add(CSpecPrototypeTestUtil.readParameterPieces(emuThread, piece,
				emulator.getLanguage().getDefaultDataSpace(), stackReg, langCompPair,
				dataConverter));
		}

		TestResult result =
			CSpecPrototypeTestUtil.getTestResult(callee, caller, pieces, fromEmulator, groundTruth);

		if (manualSelection) {
			printf("%s\n", result.message());
		}
		return result.hasError();

	}

	private LanguageCompilerSpecPair getLangCompPair(Program program) {
		return program.getLanguageCompilerSpecPair();
	}
}
