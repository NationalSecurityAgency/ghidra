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
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.AnnotatedPcodeUseropLibrary.*;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;

/**
 * A library of system calls
 *
 * <p>
 * A system call library is a collection of p-code executable routines, invoked by a system call
 * dispatcher. That dispatcher is represented by {@link #syscall(PcodeExecutor)}, and is exported as
 * a sleigh userop. If this interface is "mixed in" with {@link AnnotatedPcodeUseropLibrary}, that
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
	 * @param program
	 * @return
	 */
	public static Map<Long, PrototypeModel> loadSyscallConventionMap(Program program) {
		return loadSyscallFunctionMap(program).entrySet()
				.stream()
				.collect(Collectors.toMap(Entry::getKey, e -> e.getValue().getCallingConvention()));
	}

	/**
	 * The {@link EmuSyscallLibrary#syscall(PcodeExecutor)} method wrapped as a userop definition
	 * 
	 * @param <T> the type of data processed by the userop, typically {@code byte[]}
	 */
	final class SyscallPcodeUseropDefinition<T> implements PcodeUseropDefinition<T> {
		private final EmuSyscallLibrary<T> syslib;

		public SyscallPcodeUseropDefinition(EmuSyscallLibrary<T> syslib) {
			this.syslib = syslib;
		}

		@Override
		public String getName() {
			return "syscall";
		}

		@Override
		public int getInputCount() {
			return 0;
		}

		@Override
		public void execute(PcodeExecutor<T> executor, PcodeUseropLibrary<T> library,
				Varnode outVar, List<Varnode> inVars) {
			syslib.syscall(executor, library);
		}
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
	 * In case this is not an {@link AnnotatedEmuSyscallUseropLibrary} or
	 * {@link AnnotatedPcodeUseropLibrary}, get the definition of the "syscall" userop for inclusion
	 * in the {@link PcodeUseropLibrary}.
	 * 
	 * <p>
	 * Implementors may wish to override this to use a pre-constructed definition. That definition
	 * can be easily constructed using {@link SyscallPcodeUseropDefinition}.
	 * 
	 * @return the syscall userop definition
	 */
	default PcodeUseropDefinition<T> getSyscallUserop() {
		return new SyscallPcodeUseropDefinition<>(this);
	};

	/**
	 * Retrieve the desired system call number according to the emulated system's conventions
	 * 
	 * <p>
	 * TODO: This should go away in favor of some specification stored in the emulated program
	 * database. Until then, we require system-specific implementations.
	 * 
	 * @param state the executor's state
	 * @return the system call number
	 */
	long readSyscallNumber(PcodeExecutorStatePiece<T, T> state);

	/**
	 * Try to handle an error, usually by returning it to the user program
	 * 
	 * <p>
	 * If the particular error was not expected, it is best practice to return false, causing the
	 * emulator to interrupt. Otherwise, some state is set in the machine that, by convention,
	 * communicates the error back to the user program.
	 * 
	 * @param executor the executor for the thread that caused the error
	 * @param err the error
	 * @return true if execution can continue uninterrupted
	 */
	boolean handleError(PcodeExecutor<T> executor, PcodeExecutionException err);

	/**
	 * The entry point for executing a system call on the given executor
	 * 
	 * <p>
	 * The executor's state must already be prepared according to the relevant system calling
	 * conventions. This will determine the system call number, according to
	 * {@link #readSyscallNumber(PcodeExecutorStatePiece)}, retrieve the relevant system call
	 * definition, and invoke it.
	 * 
	 * @param executor the executor
	 * @param library the library
	 */
	@PcodeUserop
	default void syscall(@OpExecutor PcodeExecutor<T> executor,
			@OpLibrary PcodeUseropLibrary<T> library) {
		long syscallNumber = readSyscallNumber(executor.getState());
		EmuSyscallDefinition<T> syscall = getSyscalls().get(syscallNumber);
		if (syscall == null) {
			throw new EmuInvalidSystemCallException(syscallNumber);
		}
		try {
			syscall.invoke(executor, library);
		}
		catch (PcodeExecutionException e) {
			if (!handleError(executor, e)) {
				throw e;
			}
		}
	}

	/**
	 * Get the map of syscalls by number
	 * 
	 * <p>
	 * Note this method will be invoked for every emulated syscall, so it should be a simple
	 * accessor. Any computations needed to create the map should be done ahead of time.
	 * 
	 * @return the system call map
	 */
	Map<Long, EmuSyscallDefinition<T>> getSyscalls();
}
