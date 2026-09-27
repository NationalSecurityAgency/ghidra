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
package ghidra.pcode.emu.sys;

import java.io.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.pcode.emu.jit.folding.MaskedBytes;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.AnnotatedPcodeUseropLibrary.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;

/**
 * A library of system calls
 * <p>
 * A system call library is a collection of p-code executable routines, invoked by a system call
 * dispatcher. That dispatcher is represented by
 * {@link #emu_syscall(PcodeExecutor, PcodeUseropLibrary, PcodeOp, Varnode)}, and is exported as a
 * Sleigh userop. If this interface is "mixed in" with {@link AnnotatedPcodeUseropLibrary}, that
 * userop is automatically included in the userop library. The simplest means of implementing a
 * syscall library is probably via {@link AnnotatedEmuSyscallUseropLibrary}. It implements this
 * interface and extends {@link AnnotatedPcodeUseropLibrary}. In addition, it provides its own
 * annotation system for exporting userops as system calls.
 *
 * @param <T> the type of data processed by the system calls, typically {@code byte[]}
 */
public interface EmuSyscallLibrary<T> extends PcodeUseropLibrary<T> {
	String SYSCALL_SPACE_NAME = "syscall";
	String SYSCALL_CONVENTION_NAME = "syscall";

	/**
	 * Derive a syscall number to name map from the specification in a given file.
	 * 
	 * @param dataFileName the file name to be found in a modules data directory
	 * @return the map
	 * @throws IOException if the file could not be read
	 */
	public static Map<Long, String> loadSyscallNumberMap(String dataFileName) throws IOException {
		ResourceFile mapFile = Application.findDataFileInAnyModule(dataFileName);
		if (mapFile == null) {
			throw new FileNotFoundException("Cannot find syscall number map: " + dataFileName);
		}
		Map<Long, String> result = new HashMap<>();

		final BufferedReader reader =
			new BufferedReader(new InputStreamReader(mapFile.getInputStream()));
		String line;
		while (null != (line = reader.readLine())) {
			line = line.strip();
			if (line.startsWith("#")) {
				continue;
			}
			String[] parts = line.split("\\s+");
			if (parts.length != 2) {
				throw new IOException(
					"Badly formatted syscall number map: " + dataFileName + ". Line: " + line);
			}
			try {
				result.put(Long.parseLong(parts[0]), parts[1]);
			}
			catch (NumberFormatException e) {
				throw new IOException("Badly formatted syscall number map: " + dataFileName, e);
			}
		}
		return result;
	}

	/**
	 * Scrape functions from the given program's "syscall" space.
	 * 
	 * @param program the program
	 * @return a map of syscall number to function
	 */
	public static Map<Long, Function> loadSyscallFunctionMap(Program program) {
		AddressSpace space = program.getAddressFactory().getAddressSpace(SYSCALL_SPACE_NAME);
		if (space == null) {
			throw new IllegalStateException(
				"No syscall address space in program. Please analyze the syscalls first.");
		}
		Map<Long, Function> result = new HashMap<>();
		SymbolIterator sit =
			program.getSymbolTable().getSymbolIterator(space.getMinAddress(), true);
		while (sit.hasNext()) {
			Symbol s = sit.next();
			if (s.getAddress().getAddressSpace() != space) {
				break;
			}
			if (s.getSymbolType() != SymbolType.FUNCTION) {
				continue;
			}
			result.put(s.getAddress().getOffset(), (Function) s.getObject());
		}
		return result;
	}

	/**
	 * Derive a syscall number to name map by scraping functions in the program's "syscall" space.
	 * 
	 * @param program the program, likely analyzed for system calls already
	 * @return the map
	 */
	public static Map<Long, String> loadSyscallNumberMap(Program program) {
		return loadSyscallFunctionMap(program).entrySet()
				.stream()
				.collect(Collectors.toMap(Entry::getKey, e -> e.getValue().getName()));
	}

	/**
	 * Derive a syscall number to calling convention map by scraping functions in the program's
	 * "syscall" space.
	 * 
	 * @param program the program whose "syscall" space to scrape
	 * @return the map of syscall number to calling convention
	 */
	public static Map<Long, PrototypeModel> loadSyscallConventionMap(Program program) {
		return loadSyscallFunctionMap(program).entrySet()
				.stream()
				.collect(Collectors.toMap(Entry::getKey, e -> e.getValue().getCallingConvention()));
	}

	/**
	 * The definition of a system call
	 * 
	 * @param <T> the type of data processed by the system call, typically {@code byte[]}.
	 */
	interface EmuSyscallDefinition<T> {
		/**
		 * Invoke the system call
		 * 
		 * @param executor the executor for the system/thread invoking the call
		 * @param library the complete sleigh userop library for the system
		 */
		void invoke(PcodeExecutor<T> executor, PcodeUseropLibrary<T> library);
	}

	/**
	 * A Java-callback implementation of "emu_syscall" that reads the syscall number and dispatches
	 * to the appropriate system call implementation at run time.
	 * <p>
	 * This is the normal behavior for the interpretation-based p-code emulator anyway. However, for
	 * an execution engine that attempts to resolve system calls "just in time," it may be necessary
	 * to explicitly defer to this implementation to prevent any further attempt to resolve the
	 * system call, when it becomes impossible to do so.
	 * 
	 * @param executor the executor
	 * @param library the p-code userop library (often including exported system calls)
	 * @param syscallNumber the system call number
	 */
	@PcodeUserop(canInline = false)
	default void emu_rt_syscall(@OpExecutor PcodeExecutor<T> executor,
			@OpLibrary PcodeUseropLibrary<T> library, long syscallNumber) {
		EmuSyscallDefinition<T> syscall = getSyscalls().get(syscallNumber);
		if (syscall == null) {
			throw new EmuInvalidSystemCallException(syscallNumber);
		}
		syscall.invoke(executor, library);
	}

	/**
	 * The Sleigh code to defer to run-time system call resolution
	 */
	SleighPcodeUseropDefinition FALLBACK_EMU_SYSCALL =
		SleighPcodeUseropDefinition.FACTORY.define("emu_syscall")
				.params("number")
				.body(_ -> """
						__op_output = emu_rt_syscall(number);
						""")
				.build();

	/**
	 * The entry point for executing a system call on the given executor
	 * <p>
	 * The executor's state must already be prepared according to the relevant system calling
	 * conventions. The extended or composed library must provide the "syscall" and/or other
	 * relevant userops defined in the Sleigh. That "syscall" userop should invoke this userop,
	 * passing the system call number then place the result where it belongs according to the target
	 * ABI.
	 * 
	 * @param executor the executor
	 * @param library the library
	 * @param op the callother userop
	 * @param syscallNumber the varnode containing the syscall number
	 * @implNote At run time, the logic here will do exactly as it says. For the
	 *           interpretation-based emulator, nothing special happens. We read the system call
	 *           number and defer to {@link #emu_rt_syscall}, which looks it up and executes it. The
	 *           try-catch for {@link ConcretionError} appears totally useless.
	 *           <p>
	 *           For the JIT-accelerated emulator, things are more interesting. Because
	 *           {@link PcodeUserop#canInline()} is set here, we receive this callback during the
	 *           decode phase of the translation. We read the system call number and defer to
	 *           {@link #emu_rt_syscall} as before. (Note that {@link PcodeUserop#canInline()} being
	 *           false does not prevent us from invoking it from Java, even though the engine is
	 *           currently trying to inline us.) The try-catch thus protects the attempt to
	 *           concretize the syscall number. During decode, {@code T := }{@link MaskedBytes}, so
	 *           if the syscall turns out to be a constant (which it often does), then we can
	 *           dispatch it at decode time. That syscall (or at least the logic that reads
	 *           arguments and stores the result) can thus be inlined. If concretization fails, then
	 *           we fall back to invoking {#emu_rt_syscall} at run time.
	 */
	@PcodeUserop(canInline = true)
	default void emu_syscall(@OpExecutor PcodeExecutor<T> executor,
			@OpLibrary PcodeUseropLibrary<T> library, @OpOp PcodeOp op, Varnode syscallNumber) {
		T tSyscallNo = executor.getState().getVar(syscallNumber, executor.getReason());
		try {
			long lSyscallNo = executor.getArithmetic().toLong(tSyscallNo, Purpose.OTHER);
			emu_rt_syscall(executor, library, lSyscallNo);
		}
		catch (ConcretionError e) {
			FALLBACK_EMU_SYSCALL.<T> cast().execute(executor, library, op);
		}
	}

	/**
	 * Get the map of syscalls by number
	 * <p>
	 * Note this method will be invoked for every interpreted syscall, so it should be a simple
	 * accessor. Any computations needed to create the map should be done ahead of time.
	 * 
	 * @return the system call map
	 */
	Map<Long, EmuSyscallDefinition<T>> getSyscalls();
}
