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
package ghidra.app.util.opinion;

import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jdom2.JDOMException;

import db.Transaction;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.AddressEvaluator;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.target.DBTraceObjectManager;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.modules.TraceModuleManager;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.target.TraceObjectManager;
import ghidra.trace.model.target.TraceObjectManager.BypassWriteCache;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.target.schema.*;
import ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class TenetPlusPlusLoader implements Loader {
	private record ModuleEvent(String path, String module, AddressRange range) {}

	private static final String TRACE_SUFFIX = ".trace";
	private static final String TENET_SUFFIX = ".tenet";
	private static final Set<String> SUFFIXES = Set.of(TRACE_SUFFIX, TENET_SUFFIX);

	private static final Pattern TID_PATTERN = Pattern.compile("tid=([0-9a-fA-F]+),");
	private static final Pattern REG_PATTERN =
		Pattern.compile("(?:^|,)(?!(?:mr|mw|ma|slide)=)([a-zA-Z0-9]+)=0x([0-9a-fA-F]+)");
	private static final Pattern MEM_PATTERN =
		Pattern.compile("(?:^|,)(mr|mw|ma)=0x([^:]+):([0-9a-fA-F]+)");
	private static final Pattern MODULE_LOAD_PATTERN =
		Pattern.compile("Loaded image: 0x([0-9a-fA-F]+):0x([0-9a-fA-F]+) -> (.*)$");
	private static final Pattern MODULE_UNLOAD_PATTERN =
		Pattern.compile("Unloaded image: 0x([0-9a-fA-F]+):0x([0-9a-fA-F]+) -> (.*)$");

	static final int ERROR_THRESHOLD = 10;

	static final String DOMAIN_FILE_OPTION_NAME = "Program to associate trace file with";

	private static final String TENET_PLUS_PLUS_CTX_XML = """
			<context>
			    <schema name='TenetPlusPlusSession' canonical='yes'>
				    <interface name='Aggregate'/>
			        <interface name='Process'/>
			        <attribute name='Threads' schema='ThreadContainer' />
					<attribute name='Memory' schema='Memory'/>
					<attribute name='Breakpoints' schema='BreakpointContainer'/>
			        <attribute name='Modules' schema='ModuleContainer'/>
			    </schema>
			    <schema name='ThreadContainer' canonical='yes'>
			        <element schema='Thread' />
			    </schema>
			    <schema name='Thread'>
				    <interface name='Aggregate'/>
			        <interface name='Thread'/>
				    <interface name='ExecutionStateful'/>
					<attribute name='Stack' schema='Stack'/>
			    </schema>
			    <schema name='Stack' canonical='yes'>
			        <interface name='Stack'/>
			        <interface name='Aggregate'/>
			        <element schema='Frame'/>
			    </schema>
			    <schema name='Frame'>
			        <interface name='Aggregate'/>
			        <interface name='StackFrame'/>
			        <attribute name='Registers' schema='RegisterContainer'/>
			    </schema>
			    <schema name='RegisterContainer'>
			        <interface name='RegisterContainer'/>
			        <element schema='Register'/>
			    </schema>
			    <schema name='Register'>
			        <interface name='Register'/>
			    </schema>
			    <schema name='Memory' canonical='yes'>
			        <interface name='Memory'/>
			        <element schema='MemoryRegion'/>
			    </schema>
			    <schema name='MemoryRegion'>
			        <interface name='MemoryRegion'/>
			    </schema>
			    <schema name='ModuleContainer' canonical='yes'>
			        <element schema='Module'/>
			    </schema>
			    <schema name='Module'>
			        <interface name='Module'/>
			        <attribute name='Sections' schema='SectionContainer'/>
			    </schema>
			    <schema name='SectionContainer' canonical='yes'>
			        <element schema='Section'/>
			    </schema>
			    <schema name='Section'>
			        <interface name='Section'/>
			    </schema>
			    <schema name='BreakpointContainer' canonical='yes'>
			        <element schema='Breakpoint'/>
			    </schema>
			    <schema name='Breakpoint'>
			        <interface name='BreakpointSpec'/>
			        <interface name='BreakpointLocation'/>
			    </schema>
			</context>
			""";
	private static final SchemaContext SCHEMA_CTX;
	private static final TraceObjectSchema TENET_PLUS_PLUS_SESSION_SCHEMA;

	static {
		try {
			SCHEMA_CTX = XmlSchemaContext.deserialize(TENET_PLUS_PLUS_CTX_XML);
		}
		catch (final JDOMException e) {
			throw new AssertionError(e);
		}
		TENET_PLUS_PLUS_SESSION_SCHEMA =
			SCHEMA_CTX.getSchema(new SchemaName("TenetPlusPlusSession"));
	}

	private String STORE_REGS_AS_ATTRS_OPTION_NAME = "Store registers as attributes in model";
	private boolean storeRegsAsAttrs = false;
	private String ADD_ALL_MEM_REFS_OPTION_NAME = "Add all memory references";
	private boolean addAllMemRefs = false;

	private static boolean isTenetPlusPlusFile(final ByteProvider provider) {
		final String nameLower = provider.getName().toLowerCase();

		if (!SUFFIXES.stream().anyMatch(nameLower::endsWith)) {
			return false;
		}

		try {
			final byte[] bytes = new byte[1000];
			provider.getInputStream(0).read(bytes);
			final String[] lines = new String(bytes, StandardCharsets.UTF_8).split("\n");

			// Skip last line as it could be a partial one
			for (int i = 0; i < (lines.length - 1); i++) {
				final String line = lines[i];
				if ((!MODULE_LOAD_PATTERN.matcher(line).find() &&
					!MODULE_UNLOAD_PATTERN.matcher(line).find()) &&
					(!TID_PATTERN.matcher(line).find() && !REG_PATTERN.matcher(line).find())) {
					return false;
				}
			}

			return true;
		}
		catch (final IOException e) {
			return false;
		}
	}

	private AddressSpace defaultSpace;

	private Program program;

	private void addModuleEventsToSnap(Trace trace, Long snap, List<ModuleEvent> load,
			List<ModuleEvent> unload) throws DuplicateNameException {
		final TraceModuleManager modMan = trace.getModuleManager();
		if (!unload.isEmpty()) {
			for (final ModuleEvent event : unload) {
				final TraceModule module = modMan.getLoadedModuleByPath(snap, event.path());
				if (module != null) {
					module.remove(snap);
				}
			}
			unload.clear();
		}

		if (!load.isEmpty()) {
			for (final ModuleEvent event : load) {
				modMan.addLoadedModule(event.path, event.module, event.range, snap);
			}

			load.clear();
		}
	}

	/**
	 * Create an address in the processor's default space.
	 *
	 * @param offset the byte offset
	 * @return the address
	 */
	private Address addr(final long offset) {
		return defaultSpace.getAddress(offset);
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(final ByteProvider provider)
			throws IOException {
		final List<LoadSpec> loadSpecs = new ArrayList<>();
		if (isTenetPlusPlusFile(provider)) {
			// TODO: This LanguageCompilerSpecPair is not used by the loader
			// just putting a dummy value in so the user doesn't have to
			loadSpecs.add(new LoadSpec(this, 0,
				new LanguageCompilerSpecPair("DATA:LE:64:default", "pointer64"), true));
		}
		return loadSpecs;
	}

	@Override
	public List<Option> getDefaultOptions(final ByteProvider provider, final LoadSpec loadSpec,
			final DomainObject domainObject, final boolean loadIntoProgram,
			final boolean mirrorFsLayout) {
		final List<Option> list = new ArrayList<>();
		list.add(Option.newDomainFile(DOMAIN_FILE_OPTION_NAME)
				.commandLineArgument(createArg("-associatedProgram"))
				.build());
		list.add(Option.newBoolean(STORE_REGS_AS_ATTRS_OPTION_NAME)
				.commandLineArgument("-storeRegs")
				.value(storeRegsAsAttrs)
				.build());
		list.add(Option.newBoolean(ADD_ALL_MEM_REFS_OPTION_NAME)
				.commandLineArgument("-allRefs")
				.value(addAllMemRefs)
				.build());
		return list;
	}

	@Override
	public String getName() {
		return "Tenet++ Trace Format";
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.GENERIC_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 0;
	}

	@Override
	public LoadResults<? extends DomainObject> load(final ImporterSettings settings)
			throws IOException, CancelledException, VersionException, LoadException {
		Trace trace;
		String programPath = null;

		for (final Option option : settings.options()) {
			final String name = option.getName();
			if (name.equals(DOMAIN_FILE_OPTION_NAME)) {
				programPath = (String) option.getValue();
			}
			else if (name.equals(STORE_REGS_AS_ATTRS_OPTION_NAME)) {
				storeRegsAsAttrs = (boolean) option.getValue();
			}
			else if (name.equals(ADD_ALL_MEM_REFS_OPTION_NAME)) {
				addAllMemRefs = (boolean) option.getValue();
			}
		}

		if ((programPath == null) || programPath.isBlank()) {
			throw new LoadException("No progam to associate with trace was given");
		}

		Msg.info(this, "Loading trace for %s".formatted(programPath));

		final DomainFile df = settings.project().getProjectData().getFile(programPath);
		if (!df.getContentType().equals(ProgramContentHandler.PROGRAM_CONTENT_TYPE)) {
			throw new LoadException("Selected file is not a program");
		}
		Program program = null;

		try {
			program = (Program) df.getDomainObject(this, false, false, settings.monitor());

			final long start = System.currentTimeMillis();

			trace = loadTrace(settings.provider(), settings.importName(), program,
				settings.consumer(), settings.log(), settings.monitor());

			final long loadDone = System.currentTimeMillis();

			// TODO: This is needed because
			// ghidra.trace.database.DBTraceContentHandler.createFile can't do
			// it, due to a lock in
			// ghidra.framework.data.GhidraFolderData.createFile
			final DBTraceObjectManager objManager = (DBTraceObjectManager) trace.getObjectManager();
			objManager.flushWbCaches();

			final long flushDone = System.currentTimeMillis();

			settings.log()
					.appendMsg("%d ms to load trace | %d ms to flush cache | %d ms total time"
							.formatted(loadDone - start, flushDone - loadDone, flushDone - start));

			return new LoadResults<>(new Loaded<>(trace, settings));
		}
		finally {
			if (program != null) {
				program.release(this);
			}
		}
	}

	@Override
	public void loadInto(final Program program, final ImporterSettings settings)
			throws IOException, LoadException, CancelledException {
		throw new LoadException("Cannot add Trace to a program");
	}

	private Trace loadTrace(final ByteProvider provider, final String name, final Program program,
			final Object consumer, final MessageLog log, final TaskMonitor monitor)
			throws LanguageNotFoundException, IOException, CancelledException {

		this.program = program;
		final Language lang = program.getLanguage();
		defaultSpace = lang.getAddressFactory().getDefaultAddressSpace();

		final Trace trace = new DBTrace(name, program.getCompilerSpec(), consumer);
		final TraceObjectManager om = trace.getObjectManager();

		try (Transaction tx = trace.openTransaction("Import Tenet++ Trace: %s".formatted(name));
				BypassWriteCache bypass = om.withoutWriteCache()) {

			om.createRootObject(TENET_PLUS_PLUS_SESSION_SCHEMA);

			om.createObject(KeyPath.parse("Breakpoints"))
					.insert(Lifespan.ALL, ConflictResolution.DENY);

			om.createObject(KeyPath.parse("Threads")).insert(Lifespan.ALL, ConflictResolution.DENY);

			final Pattern ipPattern = Pattern.compile(
				"(?:^|,)%s=0x([0-9a-fA-F]+)".formatted(lang.getProgramCounter().getName()),
				Pattern.CASE_INSENSITIVE);

			final BufferedReader lineCounter = new BufferedReader(
				new InputStreamReader(provider.getInputStream(0), StandardCharsets.UTF_8));
			final long numLines = lineCounter.lines().count();
			lineCounter.close();

			final Map<String, TraceThread> tidToThreadMap = new HashMap<>();
			final List<ModuleEvent> modulesToLoad = new ArrayList<>();
			final List<ModuleEvent> modulesToUnload = new ArrayList<>();

			try (BufferedReader reader = new BufferedReader(
				new InputStreamReader(provider.getInputStream(0), StandardCharsets.UTF_8))) {
				long curIp = 0;
				long lineNumber = 1;
				int errorCount = 0;
				long snapNumber = 0;

				String line = reader.readLine();
				try {
					do {
						monitor.checkCancelled();

						if (parseModuleEvents(log, line, modulesToLoad, modulesToUnload)) {
							// Module load/unload no need to continue parsing
							lineNumber++;
							line = reader.readLine();
							continue;
						}

						final Matcher tidMatcher = TID_PATTERN.matcher(line);
						final Matcher ipMatcher = ipPattern.matcher(line);
						if (!tidMatcher.find()) {
							log.appendMsg(
								"Line %d: Unable to find TID, skipping...".formatted(lineNumber));
							errorCount++;
						}
						else if (!ipMatcher.find()) {
							log.appendMsg(
								"Line %d: Unable to find PC, skipping...".formatted(lineNumber));
							errorCount++;
						}
						else {
							final TraceSnapshot snapshot = trace.getTimeManager()
									.createSnapshot("Snapshot %d".formatted(snapNumber++));
							final Long snap = snapshot.getKey();
							final String tid = tidMatcher.group(1);
							if (!tidToThreadMap.containsKey(tid)) {
								final TraceThread thread = trace.getThreadManager()
										.createThread("Threads[%s]".formatted(tid),
											"Threads[%s]".formatted(tid), snap);
								tidToThreadMap.put(tid, thread);
							}
							final TraceThread traceThread = tidToThreadMap.get(tid);
							snapshot.setEventThread(traceThread);

							if (snap == 0) {
								trace.getMemoryManager()
										.addRegion("Memory[ALL]", Lifespan.nowOn(0),
											rng(0x0, 0xFFFF_FFFF_FFFF_FFFFL), TraceMemoryFlag.READ,
											TraceMemoryFlag.EXECUTE, TraceMemoryFlag.WRITE);
							}

							addModuleEventsToSnap(trace, snap, modulesToLoad, modulesToUnload);

							curIp = Long.parseLong(ipMatcher.group(1), 16);

							if (parseRegisterOperations(log, trace, traceThread, snap, curIp, line,
								lineNumber, numLines, monitor)) {
								parseMemoryOperations(trace, snap, curIp, line, lineNumber,
									numLines, monitor);
							}
							else {
								errorCount++;
							}
						}

						if (errorCount >= ERROR_THRESHOLD) {
							throw new LoadException("Encountered too many errors with this trace");
						}

						lineNumber++;

						line = reader.readLine();
					}
					while (line != null);
				}
				catch (final CancelledException e) {
					throw e;
				}
				catch (final Exception e) {
					throw new LoadException(e);
				}
			}
		}
		return trace;
	}

	private void parseMemoryOperations(final Trace trace, final long snap, final long curIp,
			final String line, long lineNumber, long numLines, final TaskMonitor monitor)
			throws Exception {

		final Matcher memMatcher = MEM_PATTERN.matcher(line);
		monitor.initialize(memMatcher.results().count(),
			"Parsing memory operations for line %d/%d".formatted(lineNumber, numLines));
		memMatcher.reset();
		// TODO Speed this up
		while (memMatcher.find()) {
			monitor.increment();

			final RefType refType = switch (memMatcher.group(1)) {
				case "mr" -> RefType.READ;
				case "mw" -> RefType.WRITE;
				default -> RefType.READ_WRITE;
			};
			final Address address = toAddr(memMatcher.group(2));
			final byte[] bytes = NumericUtilities.convertStringToBytes(memMatcher.group(3));

			// TODO: Should we do this?
			// If it's a read/write for the same address we're gonna assume it's
			// an aggregation of memory operations, so we can't say for certain
			// that the current instruction performed both operations
			if (addAllMemRefs || (refType != RefType.READ_WRITE)) {
				trace.getReferenceManager()
						.addMemoryReference(Lifespan.at(snap), addr(curIp),
							new AddressRangeImpl(address, bytes.length), refType,
							SourceType.IMPORTED, -1);
			}
			trace.getMemoryManager().putBytes(snap, address, ByteBuffer.wrap(bytes));
		}
	}

	private boolean parseModuleEvents(final MessageLog log, String line, List<ModuleEvent> load,
			List<ModuleEvent> unload) {
		final Matcher modLoadMatcher = MODULE_LOAD_PATTERN.matcher(line);
		if (modLoadMatcher.find()) {
			log.appendMsg("Found load of %s @ %s:%s".formatted(modLoadMatcher.group(3),
				modLoadMatcher.group(2), modLoadMatcher.group(1)));

			final String mod = modLoadMatcher.group(3).replace("[", "").replace("]", "");

			load.add(new ModuleEvent("Modules[%s]".formatted(mod), mod,
				rng(Long.parseLong(modLoadMatcher.group(1), 16),
					Long.parseLong(modLoadMatcher.group(2), 16))));
			return true;
		}

		final Matcher modUnloadMatcher = MODULE_UNLOAD_PATTERN.matcher(line);
		if (modUnloadMatcher.find()) {
			log.appendMsg("Found unload of %s @ %s:%s".formatted(modUnloadMatcher.group(3),
				modUnloadMatcher.group(2), modUnloadMatcher.group(1)));

			final String mod = modUnloadMatcher.group(3).replace("[", "").replace("]", "");

			unload.add(new ModuleEvent("Modules[%s]".formatted(mod), mod,
				rng(Long.parseLong(modUnloadMatcher.group(1), 16),
					Long.parseLong(modUnloadMatcher.group(2), 16))));
			return true;
		}
		return false;
	}

	private boolean parseRegisterOperations(final MessageLog log, final Trace trace,
			final TraceThread traceThread, final long snap, final long curIp, final String line,
			final long lineNumber, long numLines, final TaskMonitor monitor) throws Exception {
		final TraceStackFrame frame =
			trace.getStackManager().getStack(traceThread, snap, true).getFrame(snap, 0, true);
		frame.setProgramCounter(Lifespan.nowOn(snap), addr(curIp));

		final KeyPath traceRegistersPath = frame.getObject().getCanonicalPath().extend("Registers");
		final TraceObject traceRegisters =
			trace.getObjectManager().createObject(traceRegistersPath);
		traceRegisters.insert(Lifespan.ALL, ConflictResolution.DENY);

		final Matcher regMatcher = REG_PATTERN.matcher(line);
		monitor.initialize(regMatcher.results().count(),
			"Parsing register operations for line %d/%d".formatted(lineNumber, numLines));
		regMatcher.reset();
		while (regMatcher.find()) {
			monitor.increment();

			final BigInteger val = new BigInteger(regMatcher.group(2), 16);
			final Register regObj = trace.getProgramView().getRegister(regMatcher.group(1));
			if (regObj == null) {
				log.appendMsg("Line %d: Register %s not found in program language!"
						.formatted(lineNumber, regMatcher.group(1)));
				return false;
			}

			if (storeRegsAsAttrs) {
				traceRegisters.setElement(Lifespan.nowOn(snap), regObj.getName(), val.longValue());
			}
			trace.getMemoryManager()
					.getMemoryRegisterSpace(frame, true)
					.setValue(snap, new RegisterValue(regObj, val));
		}
		return true;
	}

	/**
	 * Create an address range in the processor's default space.
	 *
	 * @param min the minimum byte offset
	 * @param max the maximum (inclusive) byte offset
	 * @return the range
	 */
	private AddressRange rng(final long min, final long max) {
		return new AddressRangeImpl(addr(min), addr(max));
	}

	private Address toAddr(final String addressString) {
		return AddressEvaluator.evaluate(program, addressString);
	}

	@Override
	public String validateOptions(final ByteProvider provider, final LoadSpec loadSpec,
			final List<Option> options, final Program program) {
		if (options != null) {
			for (final Option option : options) {
				final String name = option.getName();
				if (name.equals(DOMAIN_FILE_OPTION_NAME) &&
					!String.class.isAssignableFrom(option.getValueClass())) {
					return "Invalid type for option: " + name + " - " + option.getValueClass();
				}
			}
		}
		return null;
	}
}
