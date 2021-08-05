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
package ghidra.app.plugin.core.debug.service.emulation;

import java.io.IOException;
import java.math.BigInteger;
import java.util.EnumSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.google.common.collect.Range;

import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingUtils;
import ghidra.app.services.DebuggerEmulationService;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.database.DBTrace;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.modules.TraceConflictedMappingException;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.thread.TraceThreadManager;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.ComparatorMath;
import ghidra.util.DifferenceAddressSetView;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.exception.DuplicateNameException;

/**
 * A set of utilities for emulating programs without necessarily having a debugger connection.
 * 
 * <p>
 * Most of these are already integrated via the {@link DebuggerEmulationService}. Please see if that
 * service satisfies your use case before employing these directly.
 */
public enum ProgramEmulationUtils {
	;

	/**
	 * Conventional prefix for first snapshot to identify "pure emulation" traces.
	 */
	public static final String EMULATION_STARTED_AT = "Emulation started at ";

	/**
	 * Suggests a name for a new trace for emulation of the given program
	 * 
	 * @param program the program to emulate
	 * @return the suggested name
	 */
	public static String getTraceName(Program program) {
		DomainFile df = program.getDomainFile();
		if (df != null) {
			return "Emulate " + df.getName();
		}
		return "Emulate " + program.getName();
	}

	/**
	 * Suggests the initial module name for loading a program into an emulated trace
	 * 
	 * @param program the program comprising the module to "load"
	 * @return the suggested module name
	 */
	public static String getModuleName(Program program) {
		String executablePath = program.getExecutablePath();
		if (executablePath != null) {
			return executablePath;
		}
		DomainFile df = program.getDomainFile();
		if (df != null) {
			return df.getName();
		}
		return program.getName();
	}

	/**
	 * Convert permissions for a program memory block into flags for a trace memory region
	 * 
	 * @param block the block whose permissions to convert
	 * @return the corresponding set of flags
	 */
	public static Set<TraceMemoryFlag> getRegionFlags(MemoryBlock block) {
		Set<TraceMemoryFlag> result = EnumSet.noneOf(TraceMemoryFlag.class);
		int mask = block.getPermissions();
		if ((mask & MemoryBlock.READ) != 0) {
			result.add(TraceMemoryFlag.READ);
		}
		if ((mask & MemoryBlock.WRITE) != 0) {
			result.add(TraceMemoryFlag.WRITE);
		}
		if ((mask & MemoryBlock.EXECUTE) != 0) {
			result.add(TraceMemoryFlag.EXECUTE);
		}
		if ((mask & MemoryBlock.VOLATILE) != 0) {
			result.add(TraceMemoryFlag.VOLATILE);
		}
		return result;
	}

	/**
	 * Create regions for each block in a program, without relocation, and map the program in
	 * 
	 * <p>
	 * This creates a region for each loaded, non-overlay block in the program. Permissions/flags
	 * are assigned accordingly. A single static mapping is generated to cover the entire range of
	 * created regions. Note that no bytes are copied in, as that could be prohibitive for large
	 * programs. Instead, the emulator should load them, based on the static mapping, as needed.
	 * 
	 * <p>
	 * A transaction must already be started on the destination trace.
	 * 
	 * @param snapshot the destination snapshot, usually 0
	 * @param program the progam to load
	 */
	public static void loadExecutable(TraceSnapshot snapshot, Program program) {
		Trace trace = snapshot.getTrace();
		Address min = null;
		Address max = null;
		try {
			for (MemoryBlock block : program.getMemory().getBlocks()) {
				if (!block.isLoaded()) {
					continue;
				}
				if (block.isOverlay()) {
					continue;
				}
				AddressRange range = new AddressRangeImpl(block.getStart(), block.getEnd());
				min = min == null ? range.getMinAddress()
						: ComparatorMath.cmin(min, range.getMinAddress());
				max = max == null ? range.getMaxAddress()
						: ComparatorMath.cmax(max, range.getMaxAddress());
				String modName = getModuleName(program);

				// TODO: Do I populate modules, since the mapping will already be done?
				trace.getMemoryManager()
						.createRegion(
							"Modules[" + modName + "].Sections[" + block.getName() + "]",
							snapshot.getKey(), range, getRegionFlags(block));
			}
			DebuggerStaticMappingUtils.addMapping(
				new DefaultTraceLocation(trace, null, Range.atLeast(snapshot.getKey()), min),
				new ProgramLocation(program, min),
				max.subtract(min), false);
		}
		catch (TraceOverlappedRegionException | DuplicateNameException
				| TraceConflictedMappingException e) {
			throw new AssertionError(e);
		}
		// N.B. Bytes will be loaded lazily
	}

	/**
	 * Spawn a new thread in the given trace at the given creation snap
	 * 
	 * <p>
	 * This does not initialize the thread's state. It simply creates it.
	 * 
	 * @param trace the trace to contain the new thread
	 * @param snap the creation shap of the new thread
	 * @return the new thread
	 */
	public static TraceThread spawnThread(Trace trace, long snap) {
		TraceThreadManager tm = trace.getThreadManager();
		long next = tm.getAllThreads().size();
		while (!tm.getThreadsByPath("Threads[" + next + "]").isEmpty()) {
			next++;
		}
		try {
			return tm.createThread("Threads[" + next + "]", "[" + next + "]", snap);
		}
		catch (DuplicateNameException e) {
			throw new AssertionError(e);
		}
	}

	/**
	 * Initialize a thread's registers using program context and an optional stack
	 * 
	 * @param trace the trace containing the thread
	 * @param snap the destination snap for the register state
	 * @param thread the thread whose registers to initialize
	 * @param program the program whose context to use
	 * @param tracePc the program counter in the trace's memory map
	 * @param programPc the program counter in the program's memory map
	 * @param stack optionally, the region representing the thread's stack
	 */
	public static void initializeRegisters(Trace trace, long snap, TraceThread thread,
			Program program, Address tracePc, Address programPc, TraceMemoryRegion stack) {
		TraceMemoryRegisterSpace space =
			trace.getMemoryManager().getMemoryRegisterSpace(thread, true);
		if (program != null) {
			ProgramContext ctx = program.getProgramContext();
			for (Register reg : Stream.of(ctx.getRegistersWithValues())
					.map(Register::getBaseRegister)
					.collect(Collectors.toSet())) {
				RegisterValue rv = ctx.getRegisterValue(reg, programPc);
				if (!rv.hasAnyValue()) {
					continue;
				}
				// Set all the mask bits
				space.setValue(snap, new RegisterValue(reg, BigInteger.ZERO).combineValues(rv));
			}
		}
		space.setValue(snap, new RegisterValue(trace.getBaseLanguage().getProgramCounter(),
			tracePc.getOffsetAsBigInteger()));
		if (stack != null) {
			CompilerSpec cSpec = trace.getBaseCompilerSpec();
			Address sp = cSpec.stackGrowsNegative()
					? stack.getMaxAddress()
					: stack.getMinAddress();
			space.setValue(snap,
				new RegisterValue(cSpec.getStackPointer(), sp.getOffsetAsBigInteger()));
		}
	}

	/**
	 * Attempt to allocate a new stack region for the given thread
	 * 
	 * @param trace the trace containing the stack and thread
	 * @param snap the creation snap for the new region
	 * @param thread the thread for which the stack is being allocated
	 * @param size the desired size of the region
	 * @return the new region representing the allocated stack
	 * 
	 * @throws EmulatorOutOfMemoryException if the stack cannot be allocated
	 */
	public static TraceMemoryRegion allocateStack(Trace trace, long snap, TraceThread thread,
			long size) {
		AddressSpace space = trace.getBaseCompilerSpec().getStackBaseSpace();
		AddressSet except0 = new AddressSet(space.getAddress(0x1000), space.getMaxAddress());
		TraceMemoryManager mm = trace.getMemoryManager();
		AddressSetView left =
			new DifferenceAddressSetView(except0, mm.getRegionsAddressSet(snap));
		try {
			for (AddressRange candidate : left) {
				if (Long.compareUnsigned(candidate.getLength(), size) > 0) {
					AddressRange alloc = new AddressRangeImpl(candidate.getMinAddress(), size);
					return mm.createRegion(thread.getPath() + ".Stack", snap, alloc,
						TraceMemoryFlag.READ, TraceMemoryFlag.WRITE);
				}
			}
		}
		catch (AddressOverflowException | TraceOverlappedRegionException
				| DuplicateNameException e) {
			throw new AssertionError(e);
		}
		throw new EmulatorOutOfMemoryException();
	}

	/**
	 * Create a new trace with a single thread, ready for emulation of the given program
	 * 
	 * @param program the program to emulate
	 * @param pc the initial program counter for the new single thread
	 * @param consumer the consumer of the new trace
	 * @return the new trace
	 * @throws IOException if the trace cannot be created
	 */
	public static Trace launchEmulationTrace(Program program, Address pc, Object consumer)
			throws IOException {
		Trace trace = null;
		boolean success = false;
		try {
			trace = new DBTrace(getTraceName(program), program.getCompilerSpec(), consumer);
			try (UndoableTransaction tid = UndoableTransaction.start(trace, "Emulate", false)) {
				TraceSnapshot initial =
					trace.getTimeManager().createSnapshot(EMULATION_STARTED_AT + pc);
				long snap = initial.getKey();
				loadExecutable(initial, program);
				doLaunchEmulationThread(trace, snap, program, pc, pc);
				tid.commit();
			}
			success = true;
			return trace;
		}
		catch (LanguageNotFoundException e) {
			throw new AssertionError(e);
		}
		finally {
			if (!success && trace != null) {
				trace.release(consumer);
			}
		}
	}

	/**
	 * Create a new emulated thread within an existing trace
	 * 
	 * @param trace the trace to contain the new thread
	 * @param snap the creation snap for the new thread
	 * @param program the program whose context to use for initial register values
	 * @param tracePc the program counter in the trace's memory map
	 * @param programPc the program counter in the program's memory map
	 * @return the new thread
	 */
	public static TraceThread doLaunchEmulationThread(Trace trace, long snap, Program program,
			Address tracePc, Address programPc) {
		TraceThread thread = spawnThread(trace, snap);
		TraceMemoryRegion stack = allocateStack(trace, snap, thread, 0x4000);
		initializeRegisters(trace, snap, thread, program, tracePc, programPc, stack);
		return thread;
	}

	/**
	 * Same as {@link #doLaunchEmulationThread(Trace, long, Program, Address, Address)}, but within
	 * a transaction
	 */
	public static TraceThread launchEmulationThread(Trace trace, long snap, Program program,
			Address tracePc, Address programPc) {
		try (UndoableTransaction tid =
			UndoableTransaction.start(trace, "Emulate new Thread", false)) {
			TraceThread thread = doLaunchEmulationThread(trace, snap, program, tracePc, programPc);
			tid.commit();
			return thread;
		}
	}

	/**
	 * Check if the given trace is for "pure emulation"
	 * 
	 * @param trace the trace to check
	 * @return true if created for emulation, false otherwise
	 */
	public static boolean isEmulatedProgram(Trace trace) {
		TraceSnapshot snapshot = trace.getTimeManager().getSnapshot(0, false);
		if (snapshot == null) {
			return false;
		}
		if (!snapshot.getDescription().startsWith(EMULATION_STARTED_AT)) {
			return false;
		}
		return true;
	}
}
