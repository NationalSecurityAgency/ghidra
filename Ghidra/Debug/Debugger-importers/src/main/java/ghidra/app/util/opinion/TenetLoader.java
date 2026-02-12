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
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jdom2.JDOMException;

import db.Transaction;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.DomainFileOption;
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
import ghidra.trace.model.memory.TraceOverlappedRegionException;
import ghidra.trace.model.modules.TraceModuleManager;
import ghidra.trace.model.modules.TraceStaticMappingManager;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.target.TraceObjectManager;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.target.schema.*;
import ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class TenetLoader implements Loader {
	private static final String TRACE_SUFFIX = ".trace";
	private static final String TENET_SUFFIX = ".tenet";
	private static final Set<String> SUFFIXES = Set.of(TRACE_SUFFIX, TENET_SUFFIX);

	private static final Pattern SLIDE_PATTERN = Pattern.compile("slide=0x([0-9a-fA-F]+)");
	private static final Pattern MEM_PATTERN =
		Pattern.compile("(?:^|,)(mr|mw)=0x([^:]+):([0-9a-fA-F]+)");
	private static final Pattern REG_PATTERN =
		Pattern.compile("(?:^|,)(?!(?:mr|mw|slide)=)([a-zA-Z0-9]+)=0x([0-9a-fA-F]+)");

	static final int ERROR_THRESHOLD = 10;

	static final String DOMAIN_FILE_OPTION_NAME = "Program to associate trace file with";
	private static final String TENET_CTX_XML = """
			<context>
			    <schema name='TenetSession' canonical='yes'>
				    <interface name='Aggregate'/>
			        <interface name='Process'/>
			        <attribute name='Thread' schema='Thread'/>
					<attribute name='Memory' schema='Memory'/>
					<attribute name='Breakpoints' schema='BreakpointContainer'/>
			        <attribute name='Modules' schema='ModuleContainer'/>
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
	private static final SchemaContext SAMPLE_CTX;

	private static final TraceObjectSchema TENET_SESSION_SCHEMA;
	static {
		try {
			SAMPLE_CTX = XmlSchemaContext.deserialize(TENET_CTX_XML);
		}
		catch (final JDOMException e) {
			throw new AssertionError(e);
		}
		TENET_SESSION_SCHEMA = SAMPLE_CTX.getSchema(new SchemaName("TenetSession"));
	}

	private static AddressSpace defaultSpace;
	private static Program program;

	private static boolean STORE_REG_ATTRS = false;

	/**
	 * Create an address in the processor's default space.
	 *
	 * @param offset the byte offset
	 * @return the address
	 */
	private static Address addr(final long offset) {
		return defaultSpace.getAddress(offset);
	}

	private static boolean isTenetFile(final ByteProvider provider) {
		final String nameLower = provider.getName().toLowerCase();

		if (!SUFFIXES.stream().anyMatch(nameLower::endsWith)) {
			return false;
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
	private static AddressRange rng(final long min, final long max) {
		return new AddressRangeImpl(addr(min), addr(max));
	}

	private static Address toAddr(final String addressString) {
		return AddressEvaluator.evaluate(program, addressString);
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(final ByteProvider provider)
			throws IOException {
		final List<LoadSpec> loadSpecs = new ArrayList<>();
		if (isTenetFile(provider)) {
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
		list.add(new DomainFileOption(DOMAIN_FILE_OPTION_NAME, "", false));
		return list;
	}

	@Override
	public String getName() {
		return "Tenet Trace Format";
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

			trace = this.loadTrace(settings.provider(), settings.importName(), program,
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
		catch (final CancelledException e) {
			throw e;
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

		TenetLoader.program = program;
		final Language lang = program.getLanguage();
		TenetLoader.defaultSpace = lang.getAddressFactory().getDefaultAddressSpace();

		final Trace trace = new DBTrace(name, program.getCompilerSpec(), consumer);

		try (Transaction tx = trace.openTransaction("Import Tenet Trace: %s".formatted(name))) {
			final TraceObjectManager om = trace.getObjectManager();
			om.createRootObject(TENET_SESSION_SCHEMA);

			final TraceThread traceThread =
				trace.getThreadManager().createThread("Thread", "Thread", 0);

			trace.getObjectManager()
					.createObject(KeyPath.parse("Breakpoints"))
					.insert(Lifespan.ALL, ConflictResolution.DENY);

			final Pattern ipPattern = Pattern.compile(
				"(?:^|,)%s=0x([0-9a-fA-F]+)".formatted(lang.getProgramCounter().getName()),
				Pattern.CASE_INSENSITIVE);

			final BufferedReader lineCounter = new BufferedReader(
				new InputStreamReader(provider.getInputStream(0), StandardCharsets.UTF_8));
			final long numLines = lineCounter.lines().count();
			lineCounter.close();
			monitor.setMaximum(numLines);

			try (BufferedReader reader = new BufferedReader(
				new InputStreamReader(provider.getInputStream(0), StandardCharsets.UTF_8))) {
				String line = reader.readLine();
				long slideValue = 0;
				long curIp = 0;
				final Matcher slideMatcher = SLIDE_PATTERN.matcher(line);
				int lineNumber = 1;
				int errorCount = 0;
				int snapNumber = 0;

				if (slideMatcher.find()) {
					slideValue = Long.parseLong(slideMatcher.group(1), 16);
					lineNumber++;
					line = reader.readLine();
				}

				final TraceSnapshot snapshot =
					trace.getTimeManager().createSnapshot("Snapshot %d".formatted(snapNumber));
				long snap = snapshot.getKey();

				snapNumber++;

				this.setupMemoryAndMapping(program, trace, slideValue, snap);

				try {
					while (line != null) {
						monitor.checkCancelled();

						if (errorCount >= ERROR_THRESHOLD) {
							throw new LoadException("Encountered too many errors with this trace");
						}

						final Matcher ipMatcher = ipPattern.matcher(line);
						if (!ipMatcher.find()) {
							log.appendMsg(
								"Line %d: Unable to find PC, skipping...".formatted(lineNumber));
							errorCount++;
							lineNumber++;
							monitor.setProgress(lineNumber);

							line = reader.readLine();
							if (line != null) {
								snap = trace.getTimeManager()
										.createSnapshot("Snapshot %d".formatted(snapNumber))
										.getKey();
								snapNumber++;
							}
							continue;
						}
						curIp = Long.parseLong(ipMatcher.group(1), 16);

						if (!this.parseRegisterOperations(snap, curIp, line, lineNumber,
							traceThread, trace, log, monitor)) {
							errorCount++;
							lineNumber++;
							monitor.setProgress(lineNumber);

							line = reader.readLine();
							if (line != null) {
								snap = trace.getTimeManager()
										.createSnapshot("Snapshot %d".formatted(snapNumber))
										.getKey();
								snapNumber++;
							}
							continue;
						}
						this.parseMemoryOperations(snap, curIp, line, trace, monitor);

						lineNumber++;
						monitor.setProgress(lineNumber);

						line = reader.readLine();
						if (line != null) {
							snap = trace.getTimeManager()
									.createSnapshot("Snapshot %d".formatted(snapNumber))
									.getKey();
							snapNumber++;

						}
					}
				}
				catch (final CancelledException e) {
					throw e;
				}
				catch (final Exception e) {
					throw new LoadException(e);
				}
			}
		}
		catch (TraceOverlappedRegionException | DuplicateNameException e) {
			// This should not happen
			throw new AssertionError(e);
		}
		return trace;
	}

	private void parseMemoryOperations(final long snap, final long curIp, final String line,
			final Trace trace, final TaskMonitor monitor) throws Exception {

		final Matcher memMatcher = MEM_PATTERN.matcher(line);

		// TODO Speed this up
		while (memMatcher.find()) {
			monitor.checkCancelled();
			final RefType refType = memMatcher.group(1).equals("mr") ? RefType.READ : RefType.WRITE;
			final Address address = toAddr(memMatcher.group(2));
			final byte[] bytes = NumericUtilities.convertStringToBytes(memMatcher.group(3));

			trace.getReferenceManager()
					.addMemoryReference(Lifespan.at(snap), addr(curIp),
						new AddressRangeImpl(address, bytes.length), refType, SourceType.IMPORTED,
						-1);
			trace.getMemoryManager().putBytes(snap, address, ByteBuffer.wrap(bytes));
		}
	}

	private boolean parseRegisterOperations(final long snap, final long curIp, final String line,
			final int lineNumber, final TraceThread traceThread, final Trace trace,
			final MessageLog log, final TaskMonitor monitor) throws Exception {
		final TraceStackFrame frame =
			trace.getStackManager().getStack(traceThread, snap, true).getFrame(snap, 0, true);
		frame.setProgramCounter(Lifespan.nowOn(snap), addr(curIp));

		final KeyPath traceRegistersPath = frame.getObject().getCanonicalPath().extend("Registers");
		final TraceObject traceRegisters =
			trace.getObjectManager().createObject(traceRegistersPath);
		traceRegisters.insert(Lifespan.ALL, ConflictResolution.DENY);

		final Matcher regMatcher = REG_PATTERN.matcher(line);
		while (regMatcher.find()) {
			monitor.checkCancelled();

			final BigInteger val = new BigInteger(regMatcher.group(2), 16);
			final Register regObj = trace.getProgramView().getRegister(regMatcher.group(1));
			if (regObj == null) {
				log.appendMsg("Line %d: Register %s not found in program language!"
						.formatted(lineNumber, regMatcher.group(1)));
				return false;
			}

			if (STORE_REG_ATTRS) {
				traceRegisters.setElement(Lifespan.nowOn(snap), regObj.getName(), val.longValue());
			}
			trace.getMemoryManager()
					.getMemoryRegisterSpace(frame, true)
					.setValue(snap, new RegisterValue(regObj, val));
		}
		return true;
	}

	private void setupMemoryAndMapping(final Program program, final Trace trace, final long slideValue,
			final long snap) throws DuplicateNameException, TraceOverlappedRegionException {
		final TraceModuleManager modMan = trace.getModuleManager();
		final TraceStaticMappingManager mapMan = trace.getStaticMappingManager();
		final URL projectUrl = program.getDomainFile().getLocalProjectURL("");

		if (slideValue != 0) {
			Msg.info(this, "Adding slide %x".formatted(slideValue));
			mapMan.add(rng(slideValue, slideValue + program.getMemory().getSize()),
				Lifespan.nowOn(snap), projectUrl, "ram:%s".formatted(program.getImageBase()));
			modMan.addLoadedModule("Modules[%s]".formatted(program.getName()),
				program.getExecutablePath(),
				rng(slideValue, slideValue + program.getMemory().getSize()), snap);
		}
		else {
			mapMan.add(
				rng(program.getImageBase().getUnsignedOffset(),
					program.getImageBase().add(program.getMemory().getSize()).getUnsignedOffset()),
				Lifespan.nowOn(snap), projectUrl, "ram:%s".formatted(program.getImageBase()));
			modMan.addLoadedModule("Modules[%s]".formatted(program.getName()),
				program.getExecutablePath(),
				rng(program.getImageBase().getUnsignedOffset(), program.getMemory().getSize()),
				snap);
		}

		// Add one giant memory region
		// TODO: Maybe make this more accurate in the future through
		// some analysis?
		trace.getMemoryManager()
				.addRegion("Memory[ALL]", Lifespan.nowOn(0), rng(0x0, 0xFFFF_FFFF_FFFF_FFFFL),
					TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE, TraceMemoryFlag.WRITE);
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
