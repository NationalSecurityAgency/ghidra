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
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingContext.ChangeCollector;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingProposals.*;
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

	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed
	private ProgramManager programManager;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoWiring;

	private final ExecutorService executor = Executors.newSingleThreadExecutor();
	private final DebuggerStaticMappingContext context;

	private final ProgramModuleIndexer programModuleIndexer;
	private final ModuleMapProposalGenerator moduleMapProposalGenerator;

	public DebuggerStaticMappingServicePlugin(PluginTool tool) {
		super(tool);
		this.autoWiring = AutoService.wireServicesProvidedAndConsumed(this);
		this.context = new DebuggerStaticMappingContext(executor);
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
		context.addChangeListener(l);
	}

	@Override
	public void removeChangeListener(DebuggerStaticMappingChangeListener l) {
		context.removeChangeListener(l);
	}

	@Override
	public CompletableFuture<Void> changesSettled() {
		return CompletableFuture.runAsync(() -> {
		}, executor);
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
		// LATER: Could probably cut out a bit of the kruft, but this should do
		if (object instanceof Program program) {
			synchronized (context.lock) {
				if (context.programInfoByProgram.containsKey(program)) {
					CompletableFuture.runAsync(this::programsChanged, executor);
				}
			}
		}
	}

	void programsChanged() {
		try (ChangeCollector cc = context.collectChanges()) {
			Set<Program> curProgs = Stream.of(programManager.getAllOpenPrograms())
					.filter(p -> !p.isClosed()) // Double-check
					.collect(Collectors.toSet());
			context.setPrograms(cc, curProgs);
		}
	}

	private void tracesChanged() {
		try (ChangeCollector cc = context.collectChanges()) {
			Set<Trace> curTraces = traceManager.getOpenTraces()
					.stream()
					.filter(t -> !t.isClosed()) // Double-check
					.collect(Collectors.toSet());
			context.setTraces(cc, curTraces);
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
						List.of(entry.getModuleName()));
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

	@Override
	public Set<Program> openMappedProgramsInView(Trace trace, AddressSetView set, long snap,
			Set<Exception> failures) {
		Set<URL> urls = context.getMappedProgramUrlsInView(trace, set, snap);
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

	@Override
	public Set<Program> getOpenMappedProgramsAtSnap(Trace trace, long snap) {
		return context.getOpenMappedProgramsAtSnap(trace, snap);
	}

	@Override
	public ProgramLocation getOpenMappedLocation(TraceLocation loc) {
		return context.getOpenMappedLocation(loc);
	}

	@Override
	public ProgramLocation getStaticLocationFromDynamic(ProgramLocation loc) {
		return context.getStaticLocationFromDynamic(loc);
	}

	@Override
	public Set<TraceLocation> getOpenMappedLocations(ProgramLocation loc) {
		return context.getOpenMappedLocations(loc);
	}

	@Override
	public TraceLocation getOpenMappedLocation(Trace trace, ProgramLocation loc, long snap) {
		return context.getOpenMappedLocation(trace, loc, snap);
	}

	@Override
	public ProgramLocation getDynamicLocationFromStatic(TraceProgramView view,
			ProgramLocation loc) {
		return context.getDynamicLocationFromStatic(view, loc);
	}

	@Override
	public Map<Program, Collection<MappedAddressRange>> getOpenMappedViews(Trace trace,
			AddressSetView set, long snap) {
		return context.getOpenMappedViews(trace, set, snap);
	}

	@Override
	public Map<TraceSpan, Collection<MappedAddressRange>> getOpenMappedViews(Program program,
			AddressSetView set) {
		return context.getOpenMappedViews(program, set);
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
	public DomainFile findBestModuleProgram(AddressSpace space, TraceModule module, long snap) {
		return programModuleIndexer.getBestMatch(space, module, snap,
			programManager.getCurrentProgram());
	}

	@Override
	public ModuleMapProposal proposeModuleMap(TraceModule module, long snap, Program program) {
		return moduleMapProposalGenerator.proposeMap(module, snap, program);
	}

	@Override
	public ModuleMapProposal proposeModuleMap(TraceModule module, long snap,
			Collection<? extends Program> programs) {
		return moduleMapProposalGenerator.proposeBestMap(module, snap, orderCurrentFirst(programs));
	}

	@Override
	public Map<TraceModule, ModuleMapProposal> proposeModuleMaps(
			Collection<? extends TraceModule> modules, long snap,
			Collection<? extends Program> programs) {
		return moduleMapProposalGenerator.proposeBestMaps(modules, snap,
			orderCurrentFirst(programs));
	}

	@Override
	public SectionMapProposal proposeSectionMap(TraceSection section, long snap, Program program,
			MemoryBlock block) {
		return new DefaultSectionMapProposal(section, snap, program, block);
	}

	@Override
	public SectionMapProposal proposeSectionMap(TraceModule module, long snap, Program program) {
		return new SectionMapProposalGenerator(snap).proposeMap(module, program);
	}

	@Override
	public SectionMapProposal proposeSectionMap(TraceModule module, long snap,
			Collection<? extends Program> programs) {
		return new SectionMapProposalGenerator(snap).proposeBestMap(module,
			orderCurrentFirst(programs));
	}

	@Override
	public Map<TraceModule, SectionMapProposal> proposeSectionMaps(
			Collection<? extends TraceModule> modules, long snap,
			Collection<? extends Program> programs) {
		return new SectionMapProposalGenerator(snap).proposeBestMaps(modules,
			orderCurrentFirst(programs));
	}

	@Override
	public RegionMapProposal proposeRegionMap(TraceMemoryRegion region, long snap, Program program,
			MemoryBlock block) {
		return new DefaultRegionMapProposal(region, snap, program, block);
	}

	@Override
	public RegionMapProposal proposeRegionMap(Collection<? extends TraceMemoryRegion> regions,
			long snap, Program program) {
		return new RegionMapProposalGenerator(snap)
				.proposeMap(Collections.unmodifiableCollection(regions), program);
	}

	@Override
	public Map<Collection<TraceMemoryRegion>, RegionMapProposal> proposeRegionMaps(
			Collection<? extends TraceMemoryRegion> regions, long snap,
			Collection<? extends Program> programs) {
		Set<Set<TraceMemoryRegion>> groups =
			DebuggerStaticMappingProposals.groupRegionsByLikelyModule(regions);
		return new RegionMapProposalGenerator(snap).proposeBestMaps(groups, programs);
	}
}
