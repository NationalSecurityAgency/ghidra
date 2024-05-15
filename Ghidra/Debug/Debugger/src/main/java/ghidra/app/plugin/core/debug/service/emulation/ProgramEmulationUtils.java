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
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.jdom.JDOMException;

import db.Transaction;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingUtils;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingUtils.Extrema;
import ghidra.app.services.DebuggerEmulationService;
import ghidra.dbg.target.*;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.dbg.util.*;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.database.DBTrace;
import ghidra.trace.model.*;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.modules.TraceConflictedMappingException;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.thread.*;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * A set of utilities for emulating programs without necessarily having a debugger connection.
 * 
 * <p>
 * Most of these are already integrated via the {@link DebuggerEmulationService}. Please see if that
 * service satisfies your use case before employing these directly.
 */
public class ProgramEmulationUtils {
	private ProgramEmulationUtils() {
	}

	public static final String EMU_CTX_XML = """
			<context>
			    <schema name='EmuSession' elementResync='NEVER' attributeResync='NEVER'>
			        <interface name='Process' />
			        <interface name='Aggregate' />
			        <attribute name='Breakpoints' schema='BreakpointContainer' />
			        <attribute name='Memory' schema='RegionContainer' />
			        <attribute name='Modules' schema='ModuleContainer' />
			        <attribute name='Threads' schema='ThreadContainer' />
			    </schema>
			    <schema name='BreakpointContainer' canonical='yes' elementResync='NEVER'
			            attributeResync='NEVER'>
			        <interface name='BreakpointSpecContainer' />
			        <interface name='BreakpointLocationContainer' />
			        <element schema='Breakpoint' />
			    </schema>
			    <schema name='Breakpoint' elementResync='NEVER' attributeResync='NEVER'>
			        <interface name='BreakpointSpec' />
			        <interface name='BreakpointLocation' />
			    </schema>
			    <schema name='RegionContainer' canonical='yes' elementResync='NEVER'
			            attributeResync='NEVER'>
			        <element schema='Region' />
			    </schema>
			    <schema name='Region' elementResync='NEVER' attributeResync='NEVER'>
			        <interface name='MemoryRegion' />
			    </schema>
			    <schema name='ModuleContainer' canonical='yes' elementResync='NEVER'
			            attributeResync='NEVER'>
			        <element schema='Module' />
			    </schema>
			    <schema name='Module' elementResync='NEVER' attributeResync='NEVER'>
			        <interface name='Module' />
			        <attribute name='Sections' schema='SectionContainer' />
			    </schema>
			    <schema name='SectionContainer' canonical='yes' elementResync='NEVER'
			            attributeResync='NEVER'>
			        <element schema='Section' />
			    </schema>
			    <schema name='Section' elementResync='NEVER' attributeResync='NEVER'>
			        <interface name='Section' />
			    </schema>
			    <schema name='ThreadContainer' canonical='yes' elementResync='NEVER'
			            attributeResync='NEVER'>
			        <element schema='Thread' />
			    </schema>
			    <schema name='Thread' elementResync='NEVER' attributeResync='NEVER'>
			        <interface name='Thread' />
			        <interface name='Activatable' />
			        <interface name='Aggregate' />
			        <attribute name='Registers' schema='RegisterContainer' />
			    </schema>
			    <schema name='RegisterContainer' canonical='yes' elementResync='NEVER'
			            attributeResync='NEVER'>
			        <interface name='RegisterContainer' />
			        <element schema='Register' />
			    </schema>
			    <schema name='Register' elementResync='NEVER' attributeResync='NEVER'>
			        <interface name='Register' />
			    </schema>
			</context>
			""";
	public static final SchemaContext EMU_CTX;
	public static final TargetObjectSchema EMU_SESSION_SCHEMA;
	static {
		try {
			EMU_CTX = XmlSchemaContext.deserialize(EMU_CTX_XML);
		}
		catch (JDOMException e) {
			throw new AssertionError(e);
		}
		EMU_SESSION_SCHEMA = EMU_CTX.getSchema(new SchemaName("EmuSession"));
	}

	public static final String BLOCK_NAME_STACK = "STACK";

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
		int mask = block.getFlags();
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
	 * This creates a region for each loaded, block in the program. Typically, only non-overlay
	 * blocks are included. To activate an overlay space, include it in the set of
	 * {@code activeOverlays}. This will alter the mapping from the trace to the static program such
	 * that the specified overlays are effective. The gaps between overlays are mapped to their
	 * physical (non-overlay) portions. Permissions/flags are assigned accordingly. Note that no
	 * bytes are copied in, as that could be prohibitive for large programs. Instead, the emulator
	 * should load them, based on the static mapping, as needed.
	 * 
	 * <p>
	 * A transaction must already be started on the destination trace.
	 * 
	 * @param snapshot the destination snapshot, usually 0
	 * @param program the program to load
	 * @param activeOverlays which overlay spaces to use
	 */
	public static void loadExecutable(TraceSnapshot snapshot, Program program,
			List<AddressSpace> activeOverlays) {
		Trace trace = snapshot.getTrace();
		PathPattern patRegion = computePatternRegion(trace);
		Map<AddressSpace, Extrema> extremaBySpace = new HashMap<>();
		Lifespan nowOn = Lifespan.nowOn(snapshot.getKey());
		try {
			for (MemoryBlock block : program.getMemory().getBlocks()) {
				if (!DebuggerStaticMappingUtils.isReal(block)) {
					continue;
				}
				AddressRange range = new AddressRangeImpl(block.getStart(), block.getEnd());
				extremaBySpace.computeIfAbsent(range.getAddressSpace(), s -> new Extrema())
						.consider(range);
				String modName = getModuleName(program);

				// NB. No need to populate as module.
				// UI will sync from mapping, so it's obvious where the cursor is.
				String path = PathUtils.toString(patRegion
						.applyKeys(block.getStart() + "-" + modName + ":" + block.getName())
						.getSingletonPath());
				trace.getMemoryManager()
						.createRegion(path, snapshot.getKey(), range, getRegionFlags(block));
			}
			AddressSet identical = new AddressSet();
			for (Extrema extrema : extremaBySpace.values()) {
				identical.add(extrema.getMin(), extrema.getMax());
			}
			for (MemoryBlock block : program.getMemory().getBlocks()) {
				if (!block.isOverlay() ||
					!activeOverlays.contains(block.getStart().getAddressSpace())) {
					continue;
				}
				Address phys = block.getStart().getPhysicalAddress();
				DebuggerStaticMappingUtils.addMapping(
					new DefaultTraceLocation(trace, null, nowOn, phys),
					new ProgramLocation(program, block.getStart()),
					block.getSize(), false);
				identical.delete(phys, block.getEnd().getPhysicalAddress());
			}
			for (AddressRange range : identical) {
				DebuggerStaticMappingUtils.addMapping(
					new DefaultTraceLocation(trace, null, nowOn, range.getMinAddress()),
					new ProgramLocation(program, range.getMinAddress()),
					range.getLength(), false);
			}
		}
		catch (TraceOverlappedRegionException | DuplicateNameException
				| TraceConflictedMappingException e) {
			throw new AssertionError(e);
		}
		// N.B. Bytes will be loaded lazily
	}

	public static PathPattern computePattern(TargetObjectSchema root, Trace trace,
			Class<? extends TargetObject> iface) {
		PathMatcher matcher = root.searchFor(iface, true);
		PathPattern pattern = matcher.getSingletonPattern();
		if (pattern == null || pattern.countWildcards() != 1) {
			throw new IllegalArgumentException(
				"Cannot find unique " + iface.getSimpleName() + " container");
		}
		return pattern;
	}

	public static PathPattern computePatternRegion(Trace trace) {
		TargetObjectSchema root = trace.getObjectManager().getRootSchema();
		if (root == null) {
			return new PathPattern(PathUtils.parse("Memory[]"));
		}
		return computePattern(root, trace, TargetMemoryRegion.class);
	}

	public static PathPattern computePatternThread(Trace trace) {
		TargetObjectSchema root = trace.getObjectManager().getRootSchema();
		if (root == null) {
			return new PathPattern(PathUtils.parse("Threads[]"));
		}
		return computePattern(root, trace, TargetThread.class);
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
		PathPattern patThread = computePatternThread(trace);
		long next = tm.getAllThreads().size();
		String path;
		while (!tm.getThreadsByPath(path =
			PathUtils.toString(patThread.applyKeys(Long.toString(next)).getSingletonPath()))
				.isEmpty()) {
			next++;
		}
		try {
			return tm.createThread(path, "[" + next + "]", snap);
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
	 * @param stack optionally, the range for the thread's stack allocation
	 */
	public static void initializeRegisters(Trace trace, long snap, TraceThread thread,
			Program program, Address tracePc, Address programPc, AddressRange stack) {
		TraceMemoryManager memory = trace.getMemoryManager();
		if (thread instanceof TraceObjectThread ot) {
			TraceObject object = ot.getObject();
			PathPredicates regsMatcher = object.getRoot()
					.getTargetSchema()
					.searchForRegisterContainer(0, object.getCanonicalPath().getKeyList());
			if (regsMatcher.isEmpty()) {
				throw new IllegalArgumentException("Cannot create register container");
			}
			for (PathPattern regsPattern : regsMatcher.getPatterns()) {
				trace.getObjectManager()
						.createObject(TraceObjectKeyPath.of(regsPattern.getSingletonPath()));
				break;
			}
		}
		TraceMemorySpace regSpace = memory.getMemoryRegisterSpace(thread, true);
		if (program != null) {
			ProgramContext ctx = program.getProgramContext();
			for (Register reg : Stream.of(ctx.getRegistersWithValues())
					.map(Register::getBaseRegister)
					.collect(Collectors.toSet())) {
				RegisterValue rv = ctx.getRegisterValue(reg, programPc);
				if (rv == null || !rv.hasAnyValue()) {
					continue;
				}
				TraceMemoryOperations space =
					reg.getAddressSpace().isRegisterSpace() ? regSpace : memory;
				// Set all the mask bits
				space.setValue(snap, new RegisterValue(reg, BigInteger.ZERO).combineValues(rv));
			}
		}
		Register regPC = trace.getBaseLanguage().getProgramCounter();
		TraceMemoryOperations spacePC =
			regPC.getAddressSpace().isRegisterSpace() ? regSpace : memory;
		spacePC.setValue(snap, new RegisterValue(regPC,
			NumericUtilities.unsignedLongToBigInteger(tracePc.getAddressableWordOffset())));
		if (stack != null) {
			CompilerSpec cSpec = trace.getBaseCompilerSpec();
			Address sp = cSpec.stackGrowsNegative()
					? stack.getMaxAddress().addWrap(1)
					: stack.getMinAddress();
			Register regSP = cSpec.getStackPointer();
			if (regSP != null) {
				TraceMemoryOperations spaceSP =
					regSP.getAddressSpace().isRegisterSpace() ? regSpace : memory;
				spaceSP.setValue(snap,
					new RegisterValue(regSP,
						NumericUtilities.unsignedLongToBigInteger(sp.getAddressableWordOffset())));
			}
		}
	}

	public static AddressRange allocateStackCustom(Trace trace, long snap, TraceThread thread,
			Program program) {
		if (program == null) {
			return null;
		}
		AddressSpace space = trace.getBaseCompilerSpec().getStackBaseSpace();
		MemoryBlock stackBlock = program.getMemory().getBlock(BLOCK_NAME_STACK);
		if (stackBlock == null) {
			return null;
		}
		if (space != stackBlock.getStart().getAddressSpace().getPhysicalSpace()) {
			Msg.showError(ProgramEmulationUtils.class, null, "Invalid STACK block",
				"The STACK block must be in the stack's base space. Ignoring.");
			return null;
		}
		AddressRange alloc = new AddressRangeImpl(
			stackBlock.getStart().getPhysicalAddress(),
			stackBlock.getEnd().getPhysicalAddress());
		if (stackBlock.isOverlay() || DebuggerStaticMappingUtils.isReal(stackBlock)) {
			return alloc;
		}
		PathPattern patRegion = computePatternRegion(trace);
		String path = PathUtils.toString(
			patRegion.applyKeys(stackBlock.getStart() + "-STACK")
					.getSingletonPath());
		TraceMemoryManager mm = trace.getMemoryManager();
		try {
			return mm.createRegion(path, snap, alloc,
				TraceMemoryFlag.READ, TraceMemoryFlag.WRITE).getRange();
		}
		catch (TraceOverlappedRegionException e) {
			Msg.showError(ProgramEmulationUtils.class, null, "Stack conflict",
				("The STACK region %s conflicts with another: %s. " +
					"You may need to initialize the stack pointer manually.").formatted(
						alloc, e.getConflicts().iterator().next()));
			return alloc;
		}
		catch (DuplicateNameException e) {
			Msg.showError(ProgramEmulationUtils.class, null, "Stack conflict",
				("A region already exists with the same name: %s. " +
					"You may need to initialize the stack pointer manually.")
							.formatted(path));
			return alloc;
		}
	}

	/**
	 * Attempt to allocate a new stack region for the given thread
	 * 
	 * <p>
	 * If successful, this will create a dynamic memory region representing the stack. If the stack
	 * is specified by an override (STACK block) in the program, and that block overlays the image,
	 * then no region is created.
	 * 
	 * @param trace the trace containing the stack and thread
	 * @param snap the creation snap for the new region
	 * @param thread the thread for which the stack is being allocated
	 * @param program the program being emulated (to check for stack allocation override)
	 * @param size the desired size of the region
	 * @return the range allocated for the stack
	 * 
	 * @throws EmulatorOutOfMemoryException if the stack cannot be allocated
	 */
	public static AddressRange allocateStack(Trace trace, long snap, TraceThread thread,
			Program program, long size) {
		AddressRange custom = allocateStackCustom(trace, snap, thread, program);
		if (custom != null) {
			return custom;
		}
		// Otherwise, just search for an un-allocated block of the given size.
		AddressSpace space = trace.getBaseCompilerSpec().getStackBaseSpace();
		Address max = space.getMaxAddress();
		AddressSet eligible;
		if (max.getOffsetAsBigInteger().compareTo(BigInteger.valueOf(0x1000)) < 0) {
			eligible = new AddressSet(space.getMinAddress(), max);
		}
		else {
			eligible = new AddressSet(space.getAddress(0x1000), max);
		}
		TraceMemoryManager mm = trace.getMemoryManager();
		AddressSetView left =
			new DifferenceAddressSetView(eligible, mm.getRegionsAddressSet(snap));
		PathPattern patRegion = computePatternRegion(trace);
		try {
			for (AddressRange candidate : left) {
				if (Long.compareUnsigned(candidate.getLength(), size) >= 0) {
					AddressRange alloc = new AddressRangeImpl(candidate.getMinAddress(), size);
					String threadName = PathUtils.isIndex(thread.getName())
							? PathUtils.parseIndex(thread.getName())
							: thread.getName();
					String path = PathUtils.toString(
						patRegion.applyKeys(alloc.getMinAddress() + "-stack " + threadName)
								.getSingletonPath());
					return mm.createRegion(path, snap, alloc,
						TraceMemoryFlag.READ, TraceMemoryFlag.WRITE).getRange();
				}
			}
		}
		catch (AddressOverflowException | TraceOverlappedRegionException
				| DuplicateNameException e) {
			throw new AssertionError(e);
		}
		throw new EmulatorOutOfMemoryException();
	}

	protected static void createObjects(Trace trace) {
		TraceObjectManager om = trace.getObjectManager();
		om.createRootObject(EMU_SESSION_SCHEMA);

		om.createObject(TraceObjectKeyPath.parse("Breakpoints"))
				.insert(Lifespan.ALL, ConflictResolution.DENY);
		om.createObject(TraceObjectKeyPath.parse("Memory"))
				.insert(Lifespan.ALL, ConflictResolution.DENY);
		om.createObject(TraceObjectKeyPath.parse("Modules"))
				.insert(Lifespan.ALL, ConflictResolution.DENY);
		om.createObject(TraceObjectKeyPath.parse("Threads"))
				.insert(Lifespan.ALL, ConflictResolution.DENY);
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
			try (Transaction tx = trace.openTransaction("Emulate")) {
				createObjects(trace);

				TraceSnapshot initial =
					trace.getTimeManager().createSnapshot(EMULATION_STARTED_AT + pc);
				long snap = initial.getKey();
				List<AddressSpace> overlays =
					pc.getAddressSpace().isOverlaySpace() ? List.of(pc.getAddressSpace())
							: List.of();
				loadExecutable(initial, program, overlays);
				doLaunchEmulationThread(trace, snap, program, pc, pc);
			}
			trace.clearUndo();
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
		AddressRange stack;
		try {
			stack = allocateStack(trace, snap, thread, program, 0x4000);
		}
		catch (EmulatorOutOfMemoryException e) {
			Msg.warn(ProgramEmulationUtils.class,
				"Cannot allocate a stack. Please initialize manually.");
			stack = null;
		}
		initializeRegisters(trace, snap, thread, program, tracePc, programPc, stack);
		return thread;
	}

	/**
	 * Same as {@link #doLaunchEmulationThread(Trace, long, Program, Address, Address)}, but within
	 * a transaction
	 */
	public static TraceThread launchEmulationThread(Trace trace, long snap, Program program,
			Address tracePc, Address programPc) {
		try (Transaction tx = trace.openTransaction("Emulate new Thread")) {
			TraceThread thread = doLaunchEmulationThread(trace, snap, program, tracePc, programPc);
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
