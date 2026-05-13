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
import java.lang.invoke.MethodHandles;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.pcode.emu.*;
import ghidra.pcode.emu.jit.JitConfiguration;
import ghidra.pcode.emu.jit.JitConfiguration.Opt;
import ghidra.pcode.emu.jit.JitPcodeEmulator;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;

public class EmuX86GccDeobfuscateHookExampleScript extends GhidraScript {

	private static final String PROGRAM_NAME = "deobHookExample";

	// Heap allocation area
	private static final int MALLOC_REGION_SIZE = 0x1000;

	// Address used as final return location
	private static final long CONTROLLED_RETURN_OFFSET = 0;

	private PcodeEmulator emu;
	private PcodeThread<byte[]> emuThread;
	private PcodeArithmetic<byte[]> arithmetic;

	private SimpleMallocMgr mallocMgr;

	// Important breakpoint locations for hooking behavior not contained with binary (e.g., dynamic library)
	private Address mallocEntry;
	private Address freeEntry;
	private Address strlenEntry;
	private Address useStringEntry;

	// Function locations
	private Function mainFunction;
	private Address mainFunctionEntry; // start of emulation
	private Address controlledReturnAddr; // end of emulation

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

		// Identify function be emulated
		mainFunctionEntry = getSymbolAddress("main");
		mainFunction = currentProgram.getFunctionManager().getFunctionAt(mainFunctionEntry);
		useStringEntry = getSymbolAddress("use_string");

		// Identify important symbol addresses
		mallocEntry = getExternalThunkAddress("malloc");
		freeEntry = getExternalThunkAddress("free");
		strlenEntry = getExternalThunkAddress("strlen");

		// Establish emulator
		emu = new JitPcodeEmulator(currentProgram.getLanguage(), new JitConfiguration(
			Opt.REMOVE_UNUSED_OPERATIONS, Opt.EMIT_COUNTERS/*, Opt.LOG_STACK_TRACES*/),
			MethodHandles.lookup()) {

			@Override
			protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
				return super.createUseropLibrary().compose(new DeobfUseropLibrary<byte[]>());
			}

			@Override
			public boolean isSuspended() {
				// Because the monitor-cancelled listener isn't reliable
				return super.isSuspended() || monitor.isCancelled();
			}
		};
		monitor.addCancelledListener(() -> {
			// Why isn't this reliable?
			emu.setSuspended(true);
		});
		emuThread = emu.newThread();
		arithmetic = emuThread.getArithmetic();
		EmulatorUtilities.loadProgram(emu, currentProgram);

		// Initialize program counter, registers from context, and stack pointer
		// Request more stack space that normal, so we can use the extra for the heap
		EmulatorUtilities.initializeForFunction(emuThread, mainFunction,
			EmulatorUtilities.DEFAULT_STACK_SIZE + MALLOC_REGION_SIZE);
		Address stackBase =
			EmulatorUtilities.inspectStackPointer(emuThread, currentProgram.getCompilerSpec());

		// Establish simple malloc memory manager with memory region spaced relative to stack pointer 
		mallocMgr = new SimpleMallocMgr(
			stackBase.subtract(EmulatorUtilities.DEFAULT_STACK_SIZE + MALLOC_REGION_SIZE),
			MALLOC_REGION_SIZE);

		// Setup hook breakpoints
		emu.inject(mallocEntry, """
				RAX = __libc_malloc(RDI);
				__x86_64_RET();
				""");
		emu.inject(freeEntry, """
				__libc_free(RDI);
				__x86_64_RET();
				""");
		emu.inject(strlenEntry, """
				RAX = __libc_strlen(RDI);
				__x86_64_RET();
				""");
		emu.inject(useStringEntry, """
				__hook_useString(RDI);
				emu_exec_decoded();
				""");

		// Set controlled return location so we can identify return from emulated function
		controlledReturnAddr = getAddress(CONTROLLED_RETURN_OFFSET);
		emuThread.getState()
				.setVar(stackBase.add(8), 8, false, arithmetic.fromConst(controlledReturnAddr));
		emu.addBreakpoint(controlledReturnAddr, "1:1");

		emuThread.overrideCounter(mainFunctionEntry);
		emuThread.overrideContext(
			currentProgram.getProgramContext().getDisassemblyContext(mainFunctionEntry));
		Msg.debug(this, "EMU starting at " + emuThread.getCounter());

		// First call to run should break after final return
		try {
			emuThread.run();
		}
		catch (InterruptPcodeExecutionException e) {
			// Hit the breakpoint. Good.
		}
		catch (Throwable t) {
			printerr("Emulation error: " + t);
			return;
		}
	}

	private Address getAddress(long offset) {
		return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	/**
	 * Get the thunk function corresponding to an external function. Such thunks should reside
	 * within the EXTERNAL block. (Note: this is specific to the ELF import)
	 * 
	 * @param symbolName external function name
	 * @return address of thunk function which corresponds to an external function
	 * @throws NotFoundException if thunk not found
	 */
	private Address getExternalThunkAddress(String symbolName) throws NotFoundException {
		Symbol externalSymbol = currentProgram.getSymbolTable().getExternalSymbol(symbolName);
		if (externalSymbol != null && externalSymbol.getSymbolType() == SymbolType.FUNCTION) {
			Function f = (Function) externalSymbol.getObject();
			Address[] thunkAddrs = f.getFunctionThunkAddresses(false);
			if (thunkAddrs.length == 1) {
				return thunkAddrs[0];
			}
		}
		throw new NotFoundException("Failed to locate label: " + symbolName);
	}

	/**
	 * Get the global namespace symbol address which corresponds to the specified name.
	 * 
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

	public class DeobfUseropLibrary<T> extends AnnotatedPcodeUseropLibrary<T> {
		static final String SRC_X86_RET = """
				RIP = *:8 RSP;
				RSP = RSP + 8;
				return [RIP];
				""";
		PcodeProgram progRet;

		@PcodeUserop(canInline = true)
		public void __x86_64_RET(@OpExecutor PcodeExecutor<T> executor,
				@OpLibrary PcodeUseropLibrary<T> library) {
			if (progRet == null) {
				progRet = SleighProgramCompiler.compileUserop(executor.getLanguage(),
					"__x86_64_RET", List.of(), SRC_X86_RET, PcodeUseropLibrary.nil(), List.of());
			}
			progRet.execute(executor, library);
		}

		@PcodeUserop(functional = true, hasSideEffects = true)
		public long __libc_malloc(int size) throws InsufficientBytesException {
			Address memAddr = mallocMgr.malloc(size);
			return memAddr.getOffset();
		}

		@PcodeUserop(functional = true, hasSideEffects = true)
		public void __libc_free(long ptr) {
			mallocMgr.free(getAddress(ptr));
		}

		static final String SRC_STRLEN = """
				__result = 0;
				<loop>
				if (*:1 (str+__result) == 0 || __result >= maxlen) goto <exit>;
				  __result = __result + 1;
				goto <loop>;
				<exit>""";
		private PcodeProgram progStrlen;

		@PcodeUserop(canInline = true)
		public void __libc_strlen(@OpExecutor PcodeExecutor<T> executor,
				@OpLibrary PcodeUseropLibrary<T> library, @OpOutput Varnode out, Varnode start) {
			Varnode const128 =
				new Varnode(executor.getLanguage().getAddressFactory().getConstantAddress(128), 4);
			// NOTE: This assumes all calls to __libc_strlen have the same output and input varnodes
			if (progStrlen == null) {
				progStrlen = SleighProgramCompiler.compileUserop(executor.getLanguage(),
					"__libc_strlen", List.of("__result", "str", "maxlen"),
					SRC_STRLEN, PcodeUseropLibrary.nil(), List.of(out, start, const128));
			}
			progStrlen.execute(executor, library);
		}

		@PcodeUserop
		public void __hook_useString(@OpState PcodeExecutorState<T> state, long ptr) {
			Address addr = state.getLanguage().getDefaultDataSpace().getAddress(ptr);
			String str = EmulatorUtilities.decodeNullTerminatedString(state, addr);
			println("use_string: " + str); // output string argument to consoles
		}
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
		 * 
		 * @param rangeStart start of the free malloc region (i.e., Heap) which has been deemed a
		 *            safe
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
