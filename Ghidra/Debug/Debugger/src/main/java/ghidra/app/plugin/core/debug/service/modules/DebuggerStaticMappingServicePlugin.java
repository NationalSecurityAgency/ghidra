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
package ghidra.app.plugin.core.debug.service.modules;

import java.io.FileNotFoundException;
import java.net.URL;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import db.Transaction;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.events.ProgramOpenedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent;
import ghidra.app.plugin.core.debug.event.TraceOpenedPluginEvent;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingProposals.ModuleMapProposalGenerator;
import ghidra.app.plugin.core.debug.utils.ProgramLocationUtils;
import ghidra.app.plugin.core.debug.utils.ProgramURLUtils;
import ghidra.app.services.*;
import ghidra.debug.api.modules.*;
import ghidra.debug.api.modules.ModuleMapProposal.ModuleMapEntry;
import ghidra.debug.api.modules.RegionMapProposal.RegionMapEntry;
import ghidra.debug.api.modules.SectionMapProposal.SectionMapEntry;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.modules.*;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.Msg;
import ghidra.util.datastruct.ListenerSet;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

@PluginInfo(
	shortDescription = "Debugger static mapping manager",
	description = "Track and manage static mappings (program-trace relocations)",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	eventsConsumed = {
		ProgramOpenedPluginEvent.class,
		ProgramClosedPluginEvent.class,
		TraceOpenedPluginEvent.class,
		TraceClosedPluginEvent.class, },
	servicesRequired = {
		ProgramManager.class,
		DebuggerTraceManagerService.class,
	},
	servicesProvided = {
		DebuggerStaticMappingService.class,
	})
public class DebuggerStaticMappingServicePlugin extends Plugin
		implements DebuggerStaticMappingService, DomainFolderChangeListener {

	record ChangeCollector(DebuggerStaticMappingServicePlugin plugin, Set<Trace> traces,
			Set<Program> programs) implements AutoCloseable {

		static <T> Set<T> subtract(Set<T> a, Set<T> b) {
			Set<T> result = new HashSet<>(a);
			result.removeAll(b);
			return result;
		}

		public ChangeCollector(DebuggerStaticMappingServicePlugin plugin) {
			this(plugin, new HashSet<>(), new HashSet<>());
		}

		public void traceAffected(Trace trace) {
			this.traces.add(trace);
		}

		public void programAffected(Program program) {
			if (program != null) {
				this.programs.add(program);
			}
		}

		@Override
		public void close() {
			plugin.changeListeners.getProxy().mappingsChanged(traces, programs);
		}
	}

	final Map<Trace, InfoPerTrace> traceInfoByTrace = new HashMap<>();
	final Map<Program, InfoPerProgram> programInfoByProgram = new HashMap<>();
	final Map<URL, InfoPerProgram> programInfoByUrl = new HashMap<>();

	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed
	private ProgramManager programManager;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoWiring;

	final Object lock = new Object();

	final ExecutorService executor = Executors.newSingleThreadExecutor();
	private final ListenerSet<DebuggerStaticMappingChangeListener> changeListeners =
		new ListenerSet<>(DebuggerStaticMappingChangeListener.class, true);

	private final ProgramModuleIndexer programModuleIndexer;
	private final ModuleMapProposalGenerator moduleMapProposalGenerator;

	public DebuggerStaticMappingServicePlugin(PluginTool tool) {
		super(tool);
		this.autoWiring = AutoService.wireServicesProvidedAndConsumed(this);
		this.programModuleIndexer = new ProgramModuleIndexer(tool);
		this.moduleMapProposalGenerator = new ModuleMapProposalGenerator(programModuleIndexer);
	}

	@Override
	protected void dispose() {
		tool.getProject().getProjectData().removeDomainFolderChangeListener(this);
		executor.close();
		super.dispose();
	}

	@Override
	public void addChangeListener(DebuggerStaticMappingChangeListener l) {
		changeListeners.add(l);
	}

	@Override
	public void removeChangeListener(DebuggerStaticMappingChangeListener l) {
		changeListeners.remove(l);
	}

	void checkAndClearProgram(ChangeCollector cc, MappingEntry me) {
		InfoPerProgram info = programInfoByUrl.get(me.getStaticProgramUrl());
		if (info == null) {
			return;
		}
		info.clearProgram(cc, me);
	}

	void checkAndFillProgram(ChangeCollector cc, MappingEntry me) {
		InfoPerProgram info = programInfoByUrl.get(me.getStaticProgramUrl());
		if (info == null) {
			return;
		}
		info.fillProgram(cc, me);
	}

	@Override
	public CompletableFuture<Void> changesSettled() {
		return CompletableFuture.runAsync(() -> {
		}, executor);
	}

	void programsChanged() {
		try (ChangeCollector cc = new ChangeCollector(this)) {
			// Invoke change callbacks without the lock! (try must surround sync)
			synchronized (lock) {
				programsChanged(cc);
			}
		}
	}

	void programsChanged(ChangeCollector cc) {
		Set<Program> curProgs = Stream.of(programManager.getAllOpenPrograms())
				.filter(p -> !p.isClosed()) // Double-check
				.collect(Collectors.toSet());
		Set<InfoPerProgram> removed = programInfoByProgram.values()
				.stream()
				.filter(i -> !curProgs.contains(i.program) || !i.urlMatches())
				.collect(Collectors.toSet());
		processRemovedProgramInfos(cc, removed);
		Set<Program> added = ChangeCollector.subtract(curProgs, programInfoByProgram.keySet());
		processAddedPrograms(cc, added);
	}

	void processRemovedProgramInfos(ChangeCollector cc, Set<InfoPerProgram> removed) {
		for (InfoPerProgram info : removed) {
			processRemovedProgramInfo(cc, info);
		}
	}

	void processRemovedProgramInfo(ChangeCollector cc, InfoPerProgram info) {
		programInfoByProgram.remove(info.program);
		programInfoByUrl.remove(info.url);
		info.clearEntries(cc);
	}

	void processAddedPrograms(ChangeCollector cc, Set<Program> added) {
		for (Program program : added) {
			processAddedProgram(cc, program);
		}
	}

	void processAddedProgram(ChangeCollector cc, Program program) {
		InfoPerProgram info = new InfoPerProgram(this, program);
		programInfoByProgram.put(program, info);
		programInfoByUrl.put(info.url, info);
		info.fillEntries(cc);
	}

	private void tracesChanged() {
		try (ChangeCollector cc = new ChangeCollector(this)) {
			// Invoke change callbacks without the lock! (try must surround sync)
			synchronized (lock) {
				tracesChanged(cc);
			}
		}
	}

	void tracesChanged(ChangeCollector cc) {
		Set<Trace> curTraces = traceManager.getOpenTraces()
				.stream()
				.filter(t -> !t.isClosed()) // Double-check
				.collect(Collectors.toSet());
		Set<Trace> oldTraces = traceInfoByTrace.keySet();

		Set<Trace> removed = ChangeCollector.subtract(oldTraces, curTraces);
		Set<Trace> added = ChangeCollector.subtract(curTraces, oldTraces);

		processRemovedTraces(cc, removed);
		processAddedTraces(cc, added);
	}

	void processRemovedTraces(ChangeCollector cc, Set<Trace> removed) {
		for (Trace trace : removed) {
			processRemovedTrace(cc, trace);
		}
	}

	void processRemovedTrace(ChangeCollector cc, Trace trace) {
		InfoPerTrace info = traceInfoByTrace.remove(trace);
		info.removeEntries(cc);
	}

	void processAddedTraces(ChangeCollector cc, Set<Trace> added) {
		for (Trace trace : added) {
			processAddedTrace(cc, trace);
		}
	}

	void processAddedTrace(ChangeCollector cc, Trace trace) {
		InfoPerTrace info = new InfoPerTrace(this, trace);
		traceInfoByTrace.put(trace, info);
		info.resyncEntries(cc);
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramOpenedPluginEvent) {
			CompletableFuture.runAsync(this::programsChanged, executor);
		}
		else if (event instanceof ProgramClosedPluginEvent) {
			CompletableFuture.runAsync(this::programsChanged, executor);
		}
		else if (event instanceof TraceOpenedPluginEvent) {
			CompletableFuture.runAsync(this::tracesChanged, executor);
		}
		else if (event instanceof TraceClosedPluginEvent) {
			CompletableFuture.runAsync(this::tracesChanged, executor);
		}
	}

	@Override
	public void domainFileObjectOpenedForUpdate(DomainFile file, DomainObject object) {
		// This get called when a domain object is saved into the active project
		// We essentially need to update the URL, which requires examining every entry
		// TODO: Could probably cut out a bit of the kruft, but this should do
		if (object instanceof Program program) {
			synchronized (lock) {
				if (programInfoByProgram.containsKey(program)) {
					CompletableFuture.runAsync(this::programsChanged, executor);
				}
			}
		}
	}

	@Override
	public void addMapping(TraceLocation from, ProgramLocation to, long length,
			boolean truncateExisting) throws TraceConflictedMappingException {
		try (Transaction tx = from.getTrace().openTransaction("Add mapping")) {
			DebuggerStaticMappingUtils.addMapping(from, to, length, truncateExisting);
		}
	}

	@Override
	public void addMapping(MapEntry<?, ?> entry, boolean truncateExisting)
			throws TraceConflictedMappingException {
		try (Transaction tx = entry.getFromTrace().openTransaction("Add mapping")) {
			DebuggerStaticMappingUtils.addMapping(entry, truncateExisting);
		}
	}

	@Override
	public void addMappings(Collection<? extends MapEntry<?, ?>> entries, TaskMonitor monitor,
			boolean truncateExisting, String description) throws CancelledException {
		Map<Trace, List<MapEntry<?, ?>>> byTrace =
			entries.stream().collect(Collectors.groupingBy(ent -> ent.getFromTrace()));
		for (Map.Entry<Trace, List<MapEntry<?, ?>>> ent : byTrace.entrySet()) {
			Trace trace = ent.getKey();
			try (Transaction tx = trace.openTransaction(description)) {
				doAddMappings(trace, ent.getValue(), monitor, truncateExisting);
			}
		}
	}

	protected static void doAddMappings(Trace trace, Collection<MapEntry<?, ?>> entries,
			TaskMonitor monitor, boolean truncateExisting) throws CancelledException {
		for (MapEntry<?, ?> ent : entries) {
			monitor.checkCancelled();
			try {
				DebuggerStaticMappingUtils.addMapping(ent, truncateExisting);
			}
			catch (Exception e) {
				Msg.error(DebuggerStaticMappingService.class,
					"Could not add mapping " + ent + ": " + e.getMessage());
			}
		}
	}

	@Override
	public void addIdentityMapping(Trace from, Program toProgram, Lifespan lifespan,
			boolean truncateExisting) {
		try (Transaction tx = from.openTransaction("Add identity mappings")) {
			DebuggerStaticMappingUtils.addIdentityMapping(from, toProgram, lifespan,
				truncateExisting);
		}
	}

	@Override
	public void addModuleMappings(Collection<ModuleMapEntry> entries, TaskMonitor monitor,
			boolean truncateExisting) throws CancelledException {
		addMappings(entries, monitor, truncateExisting, "Add module mappings");

		Map<Program, List<ModuleMapEntry>> entriesByProgram = new HashMap<>();
		for (ModuleMapEntry entry : entries) {
			if (entry.isMemorize()) {
				entriesByProgram.computeIfAbsent(entry.getToProgram(), p -> new ArrayList<>())
						.add(entry);
			}
		}
		for (Map.Entry<Program, List<ModuleMapEntry>> ent : entriesByProgram.entrySet()) {
			try (Transaction tx = ent.getKey().openTransaction("Memorize module mapping")) {
				for (ModuleMapEntry entry : ent.getValue()) {
					ProgramModuleIndexer.addModulePaths(entry.getToProgram(),
						List.of(entry.getModule().getName()));
				}
			}
		}
	}

	@Override
	public void addSectionMappings(Collection<SectionMapEntry> entries, TaskMonitor monitor,
			boolean truncateExisting) throws CancelledException {
		addMappings(entries, monitor, truncateExisting, "Add sections mappings");
	}

	@Override
	public void addRegionMappings(Collection<RegionMapEntry> entries, TaskMonitor monitor,
			boolean truncateExisting) throws CancelledException {
		addMappings(entries, monitor, truncateExisting, "Add regions mappings");
	}

	protected <T> T noTraceInfo() {
		Msg.debug(this, "The given trace is not open in this tool " +
			"(or the service hasn't received and processed the open-trace event, yet)");
		return null;
	}

	protected <T> T noProgramInfo() {
		Msg.debug(this, "The given program is not open in this tool " +
			"(or the service hasn't received and processed the open-program event, yet)");
		return null;
	}

	protected <T> T noProject() {
		return DebuggerStaticMappingUtils.noProject(this);
	}

	protected InfoPerTrace requireTrackedInfo(Trace trace) {
		InfoPerTrace info = traceInfoByTrace.get(trace);
		if (info == null) {
			return noTraceInfo();
		}
		return info;
	}

	protected InfoPerProgram requireTrackedInfo(Program program) {
		InfoPerProgram info = programInfoByProgram.get(program);
		if (info == null) {
			return noProgramInfo();
		}
		return info;
	}

	@Override
	public Set<Program> getOpenMappedProgramsAtSnap(Trace trace, long snap) {
		synchronized (lock) {
			InfoPerTrace info = requireTrackedInfo(trace);
			if (info == null) {
				return null;
			}
			return info.getOpenMappedProgramsAtSnap(snap);
		}
	}

	@Override
	public ProgramLocation getOpenMappedLocation(TraceLocation loc) {
		synchronized (lock) {
			InfoPerTrace info = requireTrackedInfo(loc.getTrace());
			if (info == null) {
				return null;
			}
			return info.getOpenMappedProgramLocation(loc.getAddress(), loc.getLifespan());
		}
	}

	protected long getNonScratchSnap(TraceProgramView view) {
		return view.getViewport().getTop(s -> s >= 0 ? s : null);
	}

	@Override
	public ProgramLocation getStaticLocationFromDynamic(ProgramLocation loc) {
		synchronized (lock) {
			loc = ProgramLocationUtils.fixLocation(loc, true);
			TraceProgramView view = (TraceProgramView) loc.getProgram();
			Trace trace = view.getTrace();
			TraceLocation tloc = new DefaultTraceLocation(trace, null,
				Lifespan.at(getNonScratchSnap(view)), loc.getByteAddress());
			ProgramLocation mapped = getOpenMappedLocation(tloc);
			if (mapped == null) {
				return null;
			}
			return ProgramLocationUtils.replaceAddress(loc, mapped.getProgram(),
				mapped.getByteAddress());
		}
	}

	@Override
	public Set<TraceLocation> getOpenMappedLocations(ProgramLocation loc) {
		synchronized (lock) {
			InfoPerProgram info = requireTrackedInfo(loc.getProgram());
			if (info == null) {
				return null;
			}
			return info.getOpenMappedTraceLocations(loc.getByteAddress());
		}
	}

	@Override
	public TraceLocation getOpenMappedLocation(Trace trace, ProgramLocation loc, long snap) {
		synchronized (lock) {
			InfoPerProgram info = requireTrackedInfo(loc.getProgram());
			if (info == null) {
				return null;
			}
			return info.getOpenMappedTraceLocation(trace, loc.getByteAddress(), snap);
		}
	}

	@Override
	public ProgramLocation getDynamicLocationFromStatic(TraceProgramView view,
			ProgramLocation loc) {
		synchronized (lock) {
			TraceLocation tloc =
				getOpenMappedLocation(view.getTrace(), loc, getNonScratchSnap(view));
			if (tloc == null) {
				return null;
			}
			return ProgramLocationUtils.replaceAddress(loc, view, tloc.getAddress());
		}
	}

	@Override
	public Map<Program, Collection<MappedAddressRange>> getOpenMappedViews(Trace trace,
			AddressSetView set, long snap) {
		synchronized (lock) {
			InfoPerTrace info = requireTrackedInfo(trace);
			if (info == null) {
				return Map.of();
			}
			return info.getOpenMappedViews(set, Lifespan.at(snap));
		}
	}

	@Override
	public Map<TraceSpan, Collection<MappedAddressRange>> getOpenMappedViews(Program program,
			AddressSetView set) {
		synchronized (lock) {
			InfoPerProgram info = requireTrackedInfo(program);
			if (info == null) {
				return Map.of();
			}
			return info.getOpenMappedViews(set);
		}
	}

	@Override
	public Set<Program> openMappedProgramsInView(Trace trace, AddressSetView set, long snap,
			Set<Exception> failures) {
		Set<URL> urls;
		synchronized (lock) {
			InfoPerTrace info = requireTrackedInfo(trace);
			if (info == null) {
				return null;
			}
			urls = info.getMappedProgramUrlsInView(set, Lifespan.at(snap));
		}
		Set<Program> result = new HashSet<>();
		for (URL url : urls) {
			try {
				Program program = ProgramURLUtils.openDomainFileFromOpenProject(programManager,
					tool.getProject(), url, ProgramManager.OPEN_VISIBLE);
				if (program == null) {
					failures.add(new FileNotFoundException(url.toString()));
				}
				result.add(program);
			}
			catch (Exception e) {
				if (failures == null) {
					throw e;
				}
				failures.add(e);
			}
		}
		return result;
	}

	protected Collection<? extends Program> orderCurrentFirst(
			Collection<? extends Program> programs) {
		if (programManager == null) {
			return programs;
		}
		Program currentProgram = programManager.getCurrentProgram();
		if (!programs.contains(currentProgram)) {
			return programs;
		}
		Set<Program> reordered = new LinkedHashSet<>(programs.size());
		reordered.add(currentProgram);
		reordered.addAll(programs);
		return reordered;
	}

	@Override
	public DomainFile findBestModuleProgram(AddressSpace space, TraceModule module) {
		return programModuleIndexer.getBestMatch(space, module, programManager.getCurrentProgram());
	}

	@Override
	public ModuleMapProposal proposeModuleMap(TraceModule module, Program program) {
		return moduleMapProposalGenerator.proposeMap(module, program);
	}

	@Override
	public ModuleMapProposal proposeModuleMap(TraceModule module,
			Collection<? extends Program> programs) {
		return moduleMapProposalGenerator.proposeBestMap(module, orderCurrentFirst(programs));
	}

	@Override
	public Map<TraceModule, ModuleMapProposal> proposeModuleMaps(
			Collection<? extends TraceModule> modules, Collection<? extends Program> programs) {
		return moduleMapProposalGenerator.proposeBestMaps(modules, orderCurrentFirst(programs));
	}

	@Override
	public SectionMapProposal proposeSectionMap(TraceSection section, Program program,
			MemoryBlock block) {
		return new DefaultSectionMapProposal(section, program, block);
	}

	@Override
	public SectionMapProposal proposeSectionMap(TraceModule module, Program program) {
		return DebuggerStaticMappingProposals.SECTIONS.proposeMap(module, program);
	}

	@Override
	public SectionMapProposal proposeSectionMap(TraceModule module,
			Collection<? extends Program> programs) {
		return DebuggerStaticMappingProposals.SECTIONS.proposeBestMap(module,
			orderCurrentFirst(programs));
	}

	@Override
	public Map<TraceModule, SectionMapProposal> proposeSectionMaps(
			Collection<? extends TraceModule> modules, Collection<? extends Program> programs) {
		return DebuggerStaticMappingProposals.SECTIONS.proposeBestMaps(modules,
			orderCurrentFirst(programs));
	}

	@Override
	public RegionMapProposal proposeRegionMap(TraceMemoryRegion region, Program program,
			MemoryBlock block) {
		return new DefaultRegionMapProposal(region, program, block);
	}

	@Override
	public RegionMapProposal proposeRegionMap(Collection<? extends TraceMemoryRegion> regions,
			Program program) {
		return DebuggerStaticMappingProposals.REGIONS
				.proposeMap(Collections.unmodifiableCollection(regions), program);
	}

	@Override
	public Map<Collection<TraceMemoryRegion>, RegionMapProposal> proposeRegionMaps(
			Collection<? extends TraceMemoryRegion> regions,
			Collection<? extends Program> programs) {
		Set<Set<TraceMemoryRegion>> groups =
			DebuggerStaticMappingProposals.groupRegionsByLikelyModule(regions);
		return DebuggerStaticMappingProposals.REGIONS.proposeBestMaps(groups, programs);
	}
}
