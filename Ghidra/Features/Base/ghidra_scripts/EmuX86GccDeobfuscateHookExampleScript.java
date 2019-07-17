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
// a disassembled program to dump data of interest (deobfuscated data in this case).
// This script emulates the "main" function within the deobHookExampleX86 program
// (see docs/GhidraClass/ExerciseFiles/Emulation/Source) built with gcc for x86-64.
// The program's "data" array contains simple obfuscated data and has a function "deobfuscate"
// which is called for each piece of ofuscated data.  The "main" function loops through all
// the data and deobfuscates each one invoking the "use_string" function for each deobfuscated
// data.  This script hooks the functions "malloc", "free" and "use_string" where the later
// simply prints the deobfuscated string passed as an argument.
//@category Examples.Emulation
import java.util.HashMap;
import java.util.Map;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.pcode.emulate.EmulateExecutionState;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;

public class EmuX86GccDeobfuscateHookExampleScript extends GhidraScript {

	private static String PROGRAM_NAME = "deobHookExample";

	// Heap allocation area
	private static final int MALLOC_REGION_SIZE = 0x1000;

	// Address used as final return location
	private static final long CONTROLLED_RETURN_OFFSET = 0;

	private EmulatorHelper emuHelper;
	private SimpleMallocMgr mallocMgr;

	// Important breakpoint locations for hooking behavior not contained with binary (e.g., dynamic library)
	private Address mallocEntry;
	private Address freeEntry;
	private Address strlenEntry;
	private Address useStringEntry;

	// Function locations
	private Address mainFunctionEntry; // start of emulation
	private Address controlledReturnAddr; // end of emulation

	@Override
	protected void run() throws Exception {

		String format =
			currentProgram.getOptions(Program.PROGRAM_INFO).getString("Executable Format", null);

		if (currentProgram == null || !currentProgram.getName().startsWith(PROGRAM_NAME) ||
			!"x86:LE:64:default".equals(currentProgram.getLanguageID().toString()) ||
			!ElfLoader.ELF_NAME.equals(format)) {

			printerr(
				"This emulation example script is specifically intended to be executed against the\n" +
					PROGRAM_NAME +
					" program whose source is contained within the GhidraClass exercise files\n" +
					"(see docs/GhidraClass/ExerciseFiles/Emulation/" + PROGRAM_NAME + ".c).\n" +
					"This program should be compiled using gcc for x86 64-bit, imported into your project, \n" +
					"analyzed and open as the active program before running ths script.");
			return;
		}

		// Identify function be emulated
		mainFunctionEntry = getSymbolAddress("main");
		useStringEntry = getSymbolAddress("use_string");

		// Identify important symbol addresses
		mallocEntry = getExternalThunkAddress("malloc");
		freeEntry = getExternalThunkAddress("free");
		strlenEntry = getExternalThunkAddress("strlen");

		// Establish emulation helper
		emuHelper = new EmulatorHelper(currentProgram);
		try {
			// Initialize stack pointer (not used by this example)
			long stackOffset =
				(mainFunctionEntry.getAddressSpace().getMaxAddress().getOffset() >>> 1) - 0x7fff;
			emuHelper.writeRegister(emuHelper.getStackPointerRegister(), stackOffset);

			// Establish simple malloc memory manager with memory region spaced relative to stack pointer 
			mallocMgr = new SimpleMallocMgr(getAddress(stackOffset - 0x10000), MALLOC_REGION_SIZE);

			// Setup hook breakpoints
			emuHelper.setBreakpoint(mallocEntry);
			emuHelper.setBreakpoint(freeEntry);
			emuHelper.setBreakpoint(strlenEntry);
			emuHelper.setBreakpoint(useStringEntry);

			// Set controlled return location so we can identify return from emulated function
			controlledReturnAddr = getAddress(CONTROLLED_RETURN_OFFSET);
			emuHelper.writeStackValue(0, 8, CONTROLLED_RETURN_OFFSET);
			emuHelper.setBreakpoint(controlledReturnAddr);

			// This example directly manipulates the PC register to facilitate hooking
			// which must alter the PC during a breakpoint, and optional stepping which does not
			// permit an initial address to be specified.
			emuHelper.writeRegister(emuHelper.getPCRegister(), mainFunctionEntry.getOffset());
			Msg.debug(this, "EMU starting at " + emuHelper.getExecutionAddress());

			// Execution loop until return from function or error occurs
			while (!monitor.isCancelled()) {
				// Use stepping if needed for troubleshooting - although it runs much slower
				//boolean success = emuHelper.step();
				boolean success = emuHelper.run(monitor);
				Address executionAddress = emuHelper.getExecutionAddress();
				if (monitor.isCancelled()) {
					println("Emulation cancelled");
					return;
				}
				if (executionAddress.equals(controlledReturnAddr)) {
					println("Returned from function");
					return;
				}
				if (!success) {
					String lastError = emuHelper.getLastError();
					printerr("Emulation Error: " + lastError);
					return;
				}
				processBreakpoint(executionAddress);
			}
		}
		finally {
			// cleanup resources and release hold on currentProgram
			emuHelper.dispose();
		}
	}

	private Address getAddress(long offset) {
		return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	/**
	 * Perform processing for the various hook points where breakpoints have been set.
	 * @param addr current execute address where emulation has been suspended
	 * @throws Exception if an error occurs
	 */
	private void processBreakpoint(Address addr) throws Exception {

		// malloc hook
		if (addr.equals(mallocEntry)) {
			int size = emuHelper.readRegister("RDI").intValue();
			Address memAddr = mallocMgr.malloc(size);
			emuHelper.writeRegister("RAX", memAddr.getOffset());
		}

		// free hook
		else if (addr.equals(freeEntry)) {
			Address freeAddr = getAddress(emuHelper.readRegister("RDI").longValue());
			mallocMgr.free(freeAddr);
		}

		// strlen hook
		else if (addr.equals(strlenEntry)) {
			Address ptr = getAddress(emuHelper.readRegister("RDI").longValue());
			int len = 0;
			while (emuHelper.readMemoryByte(ptr) != 0) {
				++len;
				ptr = ptr.next();
			}
			emuHelper.writeRegister("RAX", len);
		}

		// use_string hook - print string
		else if (addr.equals(useStringEntry)) {
			Address stringAddr = getAddress(emuHelper.readRegister("RDI").longValue());
			String str = emuHelper.readNullTerminatedString(stringAddr, 32);
			println("use_string: " + str); // output string argument to consoles
		}

		// unexpected
		else {
			if (emuHelper.getEmulateExecutionState() != EmulateExecutionState.BREAKPOINT) {
				// assume we are stepping and simply return
				return;
			}
			throw new NotFoundException("Unhandled breakpoint at " + addr);
		}

		// force early return
		long returnOffset = emuHelper.readStackValue(0, 8, false).longValue();

		emuHelper.writeRegister(emuHelper.getPCRegister(), returnOffset);
	}

	/**
	 * Get the thunk function corresponding to an external function.  Such thunks
	 * should reside within the EXTERNAL block.  (Note: this is specific to the ELF import)
	 * @param symbolName external function name
	 * @return address of thunk function which corresponds to an external function
	 * @throws NotFoundException if thunk not found
	 */
	private Address getExternalThunkAddress(String symbolName) throws NotFoundException {
		Symbol externalSymbol = currentProgram.getSymbolTable().getExternalSymbol(symbolName);
		if (externalSymbol != null && externalSymbol.getSymbolType() == SymbolType.FUNCTION) {
			Function f = (Function) externalSymbol.getObject();
			Address[] thunkAddrs = f.getFunctionThunkAddresses();
			if (thunkAddrs.length == 1) {
				return thunkAddrs[0];
			}
		}
		throw new NotFoundException("Failed to locate label: " + symbolName);
	}

	/**
	 * Get the global namespace symbol address which corresponds to the specified name.
	 * @param symbolName global symbol name
	 * @return symbol address
	 * @throws NotFoundException if symbol not found
	 */
	private Address getSymbolAddress(String symbolName) throws NotFoundException {
		Symbol symbol = SymbolUtilities.getLabelOrFunctionSymbol(currentProgram, symbolName,
			err -> Msg.error(this, err));
		if (symbol != null) {
			return symbol.getAddress();
		}
		throw new NotFoundException("Failed to locate label: " + symbolName);
	}

	/**
	 * <code>SimpleMallocMgr</code> provides a simple malloc memory manager to be used by the
	 * malloc/free hooked implementations.
	 */
	private class SimpleMallocMgr {

		private AddressSet allocSet;
		private Map<Address, AddressRange> mallocMap = new HashMap<>();

		/**
		 * <code>SimpleMallocMgr</code> constructor.
		 * @param rangeStart start of the free malloc region (i.e., Heap) which has been
		 * deemed a safe
		 * @param byteSize
		 * @throws AddressOverflowException
		 */
		SimpleMallocMgr(Address rangeStart, int byteSize) throws AddressOverflowException {
			allocSet = new AddressSet(
				new AddressRangeImpl(rangeStart, rangeStart.addNoWrap(byteSize - 1)));
		}

		synchronized Address malloc(int byteLength) throws InsufficientBytesException {
			if (byteLength <= 0) {
				throw new IllegalArgumentException("malloc request for " + byteLength);
			}
			for (AddressRange range : allocSet.getAddressRanges()) {
				if (range.getLength() >= byteLength) {
					AddressRange mallocRange = new AddressRangeImpl(range.getMinAddress(),
						range.getMinAddress().add(byteLength - 1));
					mallocMap.put(mallocRange.getMinAddress(), mallocRange);
					allocSet.delete(mallocRange);
					return mallocRange.getMinAddress();
				}
			}
			throw new InsufficientBytesException(
				"SimpleMallocMgr failed to allocate " + byteLength + " bytes");
		}

		synchronized void free(Address mallocRangeAddr) {
			AddressRange range = mallocMap.remove(mallocRangeAddr);
			if (range == null) {
				throw new IllegalArgumentException(
					"free request for unallocated block at " + mallocRangeAddr);
			}
			allocSet.add(range);
		}
	}

}
