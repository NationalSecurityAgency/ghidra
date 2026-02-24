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
// An example script demonstrating the ability to emulate a specific portion of code within
// a disassembled program to extract return values of interest (deobfuscated data in this case)
// and generate program listing comments.
// This script emulates the "main" function within the deobExample program
// (see docs/GhidraClass/ExerciseFiles/Emulation/Source) built with gcc for x86-64.
// The program's "data" array contains simple obfuscated data and has a function "deobfuscate"
// which is called for each piece of obfuscated data.  The "main" function loops through all
// the data and deobfuscates each one invoking the "use_string" function for each deobfuscated
// data.  Breakpoints are placed on the call (and just after the call)
// to the function "deobfuscate" so that the various return values can be recorded with a comment
// placed just after the call.
//@category Examples.Emulation
import java.util.NoSuchElementException;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.pcode.emu.*;
import ghidra.pcode.exec.InterruptPcodeExecutionException;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;

public class EmuX86DeobfuscateExampleScript extends GhidraScript {

	private static final String PROGRAM_NAME = "deobExample";

	private PcodeEmulator emu;
	private PcodeThread<byte[]> emuThread;
	private PcodeArithmetic<byte[]> arithmetic;

	// Important breakpoint locations
	private Address deobfuscateCall;
	private Address deobfuscateReturn;

	// Function locations
	private Function mainFunction;
	private Address mainFunctionEntry; // start of emulation address

	// Address used as final return location
	// A breakpoint will be set here so we can determine when function execution
	// has completed.
	private static final long CONTROLLED_RETURN_OFFSET = 0;
	private Address controlledReturnAddr; // end of emulation address

	// First argument passed to deobfuscate function on last call (used for comment generation)
	private long lastDeobfuscateArg0;

	@Override
	protected void run() throws Exception {

		String format = currentProgram.getExecutableFormat();

		if (currentProgram == null || !currentProgram.getName().startsWith(PROGRAM_NAME) ||
			!"x86:LE:64:default".equals(currentProgram.getLanguageID().toString()) ||
			!ElfLoader.ELF_NAME.equals(format)) {

			printerr("""
					This emulation example script is specifically intended to be executed against
					the	%s program whose source is contained within the GhidraClass exercise files
					(see docs/GhidraClass/ExerciseFiles/Emulation/%s.c). This program should be
					compiled using gcc for x86 64-bit, imported into your project, analyzed and
					open as the active program before running ths script."""
					.formatted(PROGRAM_NAME, PROGRAM_NAME));
			return;
		}

		// Identify function to be emulated
		mainFunction = getGlobalFunctions("main").stream()
				.findFirst()
				.orElseThrow(() -> new NoSuchElementException("main"));
		mainFunctionEntry = mainFunction.getEntryPoint();

		// Obtain entry instruction in order to establish initial processor context
		Instruction entryInstr = getInstructionAt(mainFunctionEntry);
		if (entryInstr == null) {
			printerr("Instruction not found at main entry point: " + mainFunctionEntry);
			return;
		}

		// Identify important symbol addresses
		// NOTE: If the sample is recompiled the following addresses may need to be adjusted
		Instruction callSite = getCalledFromInstruction("deobfuscate");
		if (callSite == null) {
			printerr("Instruction not found at call site for: deobfuscate");
			return;
		}

		deobfuscateCall = callSite.getAddress();
		deobfuscateReturn = callSite.getFallThrough(); // instruction address immediately after deobfuscate call

		// Remove prior pre-comment
		setPreComment(deobfuscateReturn, null);

		// Establish emulator
		emu = new PcodeEmulator(currentProgram.getLanguage());
		monitor.addCancelledListener(() -> {
			emu.setSuspended(true);
		});
		emuThread = emu.newThread();
		arithmetic = emuThread.getArithmetic();
		EmulatorUtilities.loadProgram(emu, currentProgram);

		// Initialize program counter, registers from context, and stack pointer
		EmulatorUtilities.initializeForFunction(emuThread, mainFunction);
		Address stackBase =
			EmulatorUtilities.inspectStackPointer(emuThread, currentProgram.getCompilerSpec());

		// Setup breakpoints
		emu.addBreakpoint(deobfuscateCall, "1:1");
		emu.addBreakpoint(deobfuscateReturn, "1:1");

		// Set controlled return location so we can identify return from emulated function
		controlledReturnAddr = getAddress(CONTROLLED_RETURN_OFFSET);
		emuThread.getState()
				.setVar(stackBase.add(8), 8, false, arithmetic.fromConst(controlledReturnAddr));
		emu.addBreakpoint(controlledReturnAddr, "1:1");

		Msg.debug(this, "EMU starting at " + emuThread.getCounter());

		// Execution loop until return from function or error occurs
		while (!monitor.isCancelled()) {
			try {
				emuThread.run();
			}
			catch (InterruptPcodeExecutionException e) {
				// Hit a breakpoint. Good.
			}
			catch (Throwable t) {
				printerr("Emulation Error: " + t);
				return;
			}
			if (monitor.isCancelled()) {
				println("Emulation cancelled");
				return;
			}
			Address executionAddress = emuThread.getCounter();
			if (executionAddress.equals(controlledReturnAddr)) {
				println("Returned from function");
				return;
			}
			processBreakpoint(executionAddress);
		}
	}

	private Address getAddress(long offset) {
		return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	/**
	 * Perform processing for the various breakpoints.
	 * 
	 * @param addr current execute address where emulation has been suspended
	 * @throws Exception if an error occurs
	 */
	private void processBreakpoint(Address addr) throws Exception {
		if (addr.equals(deobfuscateCall)) {
			Register rdi = currentProgram.getRegister("RDI");
			lastDeobfuscateArg0 =
				emuThread.getState().inspectRegisterValue(rdi).getUnsignedValue().longValue();
		}
		else if (addr.equals(deobfuscateReturn)) {
			Register rax = currentProgram.getRegister("RAX");
			long deobfuscateReturnValue =
				emuThread.getState().inspectRegisterValue(rax).getUnsignedValue().longValue();
			String read = EmulatorUtilities.decodeNullTerminatedString(emuThread.getState(),
				getAddress(deobfuscateReturnValue));
			String str = """
					deobfuscate(src=0x%x) -> "%s"\
					""".formatted(lastDeobfuscateArg0, read);
			String comment = getPreComment(deobfuscateReturn);
			if (comment == null) {
				comment = "";
			}
			else {
				comment += "\n";
			}
			comment += str;
			println("Updated pre-comment at " + deobfuscateReturn);
			setPreComment(deobfuscateReturn, comment);
		}
	}

	private Instruction getCalledFromInstruction(String functionName) {
		Symbol s = SymbolUtilities.getExpectedLabelOrFunctionSymbol(currentProgram, functionName,
			m -> printerr(m));
		for (Reference ref : s.getReferences(monitor)) {
			if (ref.getReferenceType().isCall()) {
				return currentProgram.getListing().getInstructionAt(ref.getFromAddress());
			}
		}
		return null;
	}
}
