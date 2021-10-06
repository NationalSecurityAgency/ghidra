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
package agent.gdb.manager.impl;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.common.collect.RangeSet;

import agent.gdb.manager.*;
import agent.gdb.manager.GdbCause.Causes;
import agent.gdb.manager.GdbManager.StepCmd;
import agent.gdb.manager.impl.cmd.*;
import agent.gdb.manager.impl.cmd.GdbConsoleExecCommand.CompletesWithRunning;
import ghidra.async.AsyncLazyValue;
import ghidra.lifecycle.Internal;
import ghidra.util.Msg;

/**
 * The implementation of {@link GdbInferior}
 */
public class GdbInferiorImpl implements GdbInferior {
	protected static final Pattern MEMORY_MAPPING_LINE_PATTERN = Pattern.compile("\\s*" + //
		"0x(?<start>[0-9,A-F,a-f]+)\\s+" + //
		"0x(?<end>[0-9,A-F,a-f]+)\\s+" + //
		"0x(?<size>[0-9,A-F,a-f]+)\\s+" + //
		"0x(?<offset>[0-9,A-F,a-f]+)\\s*" + //
		"(?<file>\\S*)\\s*");

	private final GdbManagerImpl manager;
	private final int id;

	private Long pid; // Not always present
	private Long exitCode; // Not always present
	private String executable; // Not always present

	private ByteOrder endianness;

	private final Map<Integer, GdbThreadImpl> threads = new LinkedHashMap<>();
	private final Map<Integer, GdbThread> unmodifiableThreads =
		Collections.unmodifiableMap(threads);

	private final Map<String, GdbModuleImpl> modules = new LinkedHashMap<>();
	private final Map<String, GdbModule> unmodifiableModules = Collections.unmodifiableMap(modules);

	// Because asking GDB to list sections lists those of all modules
	protected final AsyncLazyValue<Void> loadSections = new AsyncLazyValue<>(this::doLoadSections);

	private final NavigableMap<BigInteger, GdbMemoryMapping> mappings = new TreeMap<>();
	private final NavigableMap<BigInteger, GdbMemoryMapping> unmodifiableMappings =
		Collections.unmodifiableNavigableMap(mappings);

	public GdbInferiorImpl(GdbManagerImpl manager, int id) {
		this.manager = manager;
		this.id = id;
	}

	/**
	 * Construct a new inferior
	 * 
	 * @param manager the manager creating the inferior
	 * @param id the GDB-assigned inferior ID
	 */
	public GdbInferiorImpl(GdbManagerImpl manager, GdbInferiorThreadGroup g) {
		this(manager, g.getInferiorId());
		update(g);
	}

	public void update(GdbInferiorThreadGroup g) {
		Long oldPid = pid;
		this.pid = g.getPid();
		this.exitCode = g.getExitCode();
		this.executable = g.getExecutable();
		
		// Because we're only called to resync, we should synth started, if needed
		if (oldPid == null && pid != null) {
			manager.fireInferiorStarted(this, Causes.UNCLAIMED, "resyncInferiorStarted");
		}
	}

	@Override
	public String toString() {
		return "<GdbInferior id=" + id + ",pid=" + pid + ",exitCode=" + exitCode + ",executable=" +
			executable + ">";
	}

	@Override
	public int getId() {
		return id;
	}

	/**
	 * Set the process ID of this inferior
	 * 
	 * An inferior is associated to exactly one process at a time, but since it may be restarted, it
	 * may be associated with different processes at different times. This method allows the manager
	 * to set the PID when it changes.
	 * 
	 * @param pid the PID
	 */
	public void setPid(long pid) {
		this.pid = pid;
	}

	@Override
	public Long getPid() {
		return pid;
	}

	/**
	 * Set the inferior exit code
	 * 
	 * When the inferior exits (or rather its associated process exits), this allows the manager to
	 * set the exit code.
	 * 
	 * @param exitCode the exit code (status or signal)
	 */
	public void setExitCode(Long exitCode) {
		this.exitCode = exitCode;
	}

	@Override
	public Long getExitCode() {
		return exitCode;
	}

	@Override
	public String getExecutable() {
		return executable;
	}

	/**
	 * Add this inferior to the manager's list of inferiors, because of a given cause
	 * 
	 * @param cause the cause of the new inferior
	 */
	public void add(GdbCause cause) {
		manager.addInferior(this, cause);
	}

	/**
	 * Remove this inferior from the manager's list of inferiors, because of a given cause
	 * 
	 * @param cause the cause of removal
	 */
	public void remove(GdbCause cause) {
		manager.removeInferior(id, cause);
	}

	/**
	 * Use {@link GdbThreadImpl#add()} instead
	 * 
	 * @param thread the thread to add
	 */
	public void addThread(GdbThreadImpl thread) {
		GdbThreadImpl exists = threads.get(thread.getId());
		if (exists != null) {
			throw new IllegalArgumentException("There is already thread " + exists);
		}
		threads.put(thread.getId(), thread);

	}

	@Override
	public GdbThreadImpl getThread(int tid) {
		GdbThreadImpl result = threads.get(tid);
		if (result == null) {
			throw new IllegalArgumentException("There is no thread with id " + tid);
		}
		return result;
	}

	/**
	 * Use {@link GdbThreadImpl#remove()} instead
	 * 
	 * @param tid the ID of the thread to remove
	 */
	public void removeThread(int tid) {
		if (threads.remove(tid) == null) {
			throw new IllegalArgumentException("There is no thread with id " + tid);
		}
	}

	@Override
	public Map<Integer, GdbThread> getKnownThreads() {
		return unmodifiableThreads;
	}

	public Map<Integer, GdbThreadImpl> getKnownThreadsImpl() {
		return threads;
	}

	protected <T> CompletableFuture<T> execute(GdbCommand<? extends T> cmd) {
		/**
		 * Queue select and execute one immediately after the other. If I do thenCompose, it's
		 * possible for some other command to get inserted between, which means this inferior may no
		 * longer be current for the actual command execution. NB: The select command will cancel
		 * itself if this inferior is already current.
		 */
		return setActive(true).thenCombine(manager.execute(cmd), (s, e) -> e);
	}

	@Override
	public CompletableFuture<Map<Integer, GdbThread>> listThreads() {
		return execute(new GdbListThreadsCommand(manager, this));
	}

	@Override
	public Map<String, GdbModule> getKnownModules() {
		return unmodifiableModules;
	}

	@Override
	public CompletableFuture<Map<String, GdbModule>> listModules() {
		// "nosections" is an unlikely section name. Goal is to exclude section lines.
		// TODO: See how this behaves on other GDB versions.
		return consoleCapture("maintenance info sections ALLOBJ nosections",
			CompletesWithRunning.CANNOT)
					.thenApply(this::parseModuleNames);
	}

	protected CompletableFuture<Void> loadSections() {
		return loadSections.request();
	}

	protected CompletableFuture<Void> doLoadSections() {
		return consoleCapture("maintenance info sections ALLOBJ", CompletesWithRunning.CANNOT)
				.thenAccept(this::parseAndUpdateAllModuleSections);
	}

	protected GdbModuleImpl resyncCreateModule(String name) {
		Msg.warn(this, "Resync: Missed loaded module/library: " + name);
		//manager.listenersInferior.fire.libraryLoaded(this, name, Causes.UNCLAIMED);
		return createModule(name);
	}

	protected GdbModuleImpl createModule(String name) {
		return new GdbModuleImpl(this, name);
	}

	protected void libraryLoaded(String name) {
		modules.computeIfAbsent(name, this::createModule);
	}

	protected void libraryUnloaded(String name) {
		modules.remove(name);
	}

	protected void resyncRetainModules(Set<String> names) {
		for (Iterator<Entry<String, GdbModuleImpl>> mit = modules.entrySet().iterator(); mit
				.hasNext();) {
			Entry<String, GdbModuleImpl> ent = mit.next();
			if (!names.contains(ent.getKey())) {
				Msg.warn(this, "Resync: Missed unloaded module/library: " + ent);
				/*manager.listenersInferior.fire.libraryUnloaded(this, ent.getKey(),
					Causes.UNCLAIMED);*/
			}
		}
	}

	protected void parseAndUpdateAllModuleSections(String out) {
		Set<String> namesSeen = new HashSet<>();
		GdbModuleImpl curModule = null;
		for (String line : out.split("\n")) {
			Matcher nameMatcher = GdbModuleImpl.OBJECT_FILE_LINE_PATTERN.matcher(line);
			if (nameMatcher.matches()) {
				if (curModule != null) {
					curModule.loadSections.provide().complete(null);
				}
				String name = nameMatcher.group("name");
				namesSeen.add(name);
				curModule = modules.computeIfAbsent(name, this::resyncCreateModule);
				// NOTE: This will usurp the module's lazy loader, but we're about to
				// provide it anyway
				if (curModule.loadSections.isDone()) {
					curModule = null;
				}
				continue;
			}
			if (curModule == null) {
				continue;
			}
			curModule.processSectionLine(line);
		}
		if (curModule != null) {
			curModule.loadSections.provide().complete(null);
		}
		resyncRetainModules(namesSeen);
	}

	protected Map<String, GdbModule> parseModuleNames(String out) {
		Set<String> namesSeen = new HashSet<>();
		for (String line : out.split("\n")) {
			Matcher nameMatcher = GdbModuleImpl.OBJECT_FILE_LINE_PATTERN.matcher(line);
			if (nameMatcher.matches()) {
				String name = nameMatcher.group("name");
				namesSeen.add(name);
				modules.computeIfAbsent(name, this::resyncCreateModule);
			}
		}
		resyncRetainModules(namesSeen);
		return unmodifiableModules;
	}

	@Override
	public Map<BigInteger, GdbMemoryMapping> getKnownMappings() {
		return unmodifiableMappings;
	}

	@Override
	public CompletableFuture<Map<BigInteger, GdbMemoryMapping>> listMappings() {
		return consoleCapture("info proc mappings", CompletesWithRunning.CANNOT)
				.thenApply(this::parseMappings);
	}

	protected Map<BigInteger, GdbMemoryMapping> parseMappings(String out) {
		Set<BigInteger> startsSeen = new TreeSet<>();
		for (String line : out.split("\n")) {
			Matcher mappingMatcher = MEMORY_MAPPING_LINE_PATTERN.matcher(line);
			if (!mappingMatcher.matches()) {
				continue;
			}
			try {
				BigInteger start = new BigInteger(mappingMatcher.group("start"), 16);
				BigInteger end = new BigInteger(mappingMatcher.group("end"), 16);
				BigInteger size = new BigInteger(mappingMatcher.group("size"), 16);
				BigInteger offset = new BigInteger(mappingMatcher.group("offset"), 16);
				String objfile = mappingMatcher.group("file");
				startsSeen.add(start);
				mappings.put(start, new GdbMemoryMapping(start, end, size, offset, objfile));
			}
			catch (NumberFormatException e) {
				Msg.error(this, "Could not parse mapping entry: " + line, e);
			}
		}
		mappings.keySet().retainAll(startsSeen);
		return unmodifiableMappings;
	}

	@Override
	public CompletableFuture<Void> setActive(boolean internal) {
		return manager.setActiveInferior(this, internal);
	}

	@Override
	public CompletableFuture<Void> fileExecAndSymbols(String file) {
		return execute(new GdbFileExecAndSymbolsCommand(manager, file));
	}

	@Override
	public CompletableFuture<GdbThread> run() {
		return execute(new GdbRunCommand(manager));
	}

	@Override
	public CompletableFuture<GdbThread> start() {
		return execute(new GdbStartCommand(manager));
	}

	@Override
	public CompletableFuture<GdbThread> starti() {
		return execute(new GdbStartInstructionCommand(manager));
	}

	@Override
	public CompletableFuture<Set<GdbThread>> attach(long toPid) {
		return execute(new GdbAttachCommand(manager, toPid));
	}

	@Override
	public CompletableFuture<Void> console(String command, CompletesWithRunning cwr) {
		return execute(new GdbConsoleExecCommand(manager, null, null, command,
			GdbConsoleExecCommand.Output.CONSOLE, cwr)).thenApply(e -> null);
	}

	@Override
	public CompletableFuture<String> consoleCapture(String command, CompletesWithRunning cwr) {
		return execute(new GdbConsoleExecCommand(manager, null, null, command,
			GdbConsoleExecCommand.Output.CAPTURE, cwr));
	}

	@Override
	public CompletableFuture<Void> cont() {
		return execute(new GdbContinueCommand(manager, null));
	}

	@Override
	public CompletableFuture<Void> step(StepCmd suffix) {
		return execute(new GdbStepCommand(manager, null, suffix));
	}

	@Override
	public CompletableFuture<String> evaluate(String expression) {
		return execute(new GdbEvaluateCommand(manager, null, null, expression));
	}

	@Override
	public CompletableFuture<Void> setTty(String tty) {
		return execute(new GdbSetInferiorTtyCommand(manager, tty));
	}

	@Override
	public CompletableFuture<String> getVar(String varName) {
		// TODO: Are these actually per-inferior?
		// If so, should make them accessible via thread
		return execute(new GdbGetVarCommand(manager, varName));
	}

	@Override
	public CompletableFuture<Void> setVar(String varName, String val) {
		// TODO: Are these actually per-inferior?
		// If so, should make them accessible via thread
		return execute(new GdbSetVarCommand(manager, null, varName, val));
	}

	@Override
	public CompletableFuture<Void> detach() {
		return execute(new GdbDetachCommand(manager, this, null));
	}

	@Override
	public CompletableFuture<Void> kill() {
		return execute(new GdbKillCommand(manager, null));
	}

	@Override
	public CompletableFuture<RangeSet<Long>> readMemory(long addr, ByteBuffer buf, int len) {
		return execute(new GdbReadMemoryCommand(manager, null, addr, buf, len));
	}

	@Override
	public CompletableFuture<Void> writeMemory(long addr, ByteBuffer buf, int len) {
		return execute(new GdbWriteMemoryCommand(manager, null, addr, buf, len));
	}

	@Override
	public CompletableFuture<Void> remove() {
		return manager.removeInferior(this);
	}

	@Override
	public String getDescriptor() {
		if (pid != null) {
			return "process " + pid;
		}
		return "<null>";
	}

	@Internal
	public CompletableFuture<Void> syncEndianness() {
		return consoleCapture("show endian", CompletesWithRunning.CANNOT).thenAccept(out -> {
			if (out.toLowerCase().contains("little endian")) {
				endianness = ByteOrder.LITTLE_ENDIAN;
			}
			else if (out.toLowerCase().contains("big endian")) {
				endianness = ByteOrder.BIG_ENDIAN;
			}
			else {
				endianness = null;
			}
		});
	}

	@Internal
	public ByteOrder getEndianness() {
		if (endianness == null) {
			throw new AssertionError("Could not determine target endianness");
		}
		return endianness;
	}
}
