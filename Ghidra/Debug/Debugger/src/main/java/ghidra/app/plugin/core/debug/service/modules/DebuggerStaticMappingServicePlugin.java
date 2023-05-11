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

import java.net.URL;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import org.apache.commons.lang3.ArrayUtils;

import db.Transaction;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.events.ProgramOpenedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent;
import ghidra.app.plugin.core.debug.event.TraceOpenedPluginEvent;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingProposals.ModuleMapProposalGenerator;
import ghidra.app.plugin.core.debug.utils.*;
import ghidra.app.services.*;
import ghidra.app.services.ModuleMapProposal.ModuleMapEntry;
import ghidra.app.services.RegionMapProposal.RegionMapEntry;
import ghidra.app.services.SectionMapProposal.SectionMapEntry;
import ghidra.async.AsyncDebouncer;
import ghidra.async.AsyncTimer;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.generic.util.datastruct.TreeValueSortedMap;
import ghidra.generic.util.datastruct.ValueSortedMap;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.Trace.TraceStaticMappingChangeType;
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
		TraceClosedPluginEvent.class,
	},
	servicesRequired = {
		ProgramManager.class,
		DebuggerTraceManagerService.class,
	},
	servicesProvided = {
		DebuggerStaticMappingService.class,
	})
public class DebuggerStaticMappingServicePlugin extends Plugin
		implements DebuggerStaticMappingService, DomainFolderChangeAdapter {

	protected class MappingEntry {
		private final TraceStaticMapping mapping;

		private Program program;
		private AddressRange staticRange;

		public MappingEntry(TraceStaticMapping mapping) {
			this.mapping = mapping;
		}

		public Trace getTrace() {
			return mapping.getTrace();
		}

		public Address addOrMax(Address start, long length) {
			Address result = start.addWrapSpace(length);
			if (result.compareTo(start) < 0) {
				Msg.warn(this, "Mapping entry caused overflow in static address space");
				return start.getAddressSpace().getMaxAddress();
			}
			return result;
		}

		public boolean programOpened(Program opened) {
			if (mapping.getStaticProgramURL().equals(ProgramURLUtils.getUrlFromProgram(opened))) {
				this.program = opened;
				Address minAddr = opened.getAddressFactory().getAddress(mapping.getStaticAddress());
				Address maxAddr = addOrMax(minAddr, mapping.getLength() - 1);
				this.staticRange = new AddressRangeImpl(minAddr, maxAddr);
				return true;
			}
			return false;
		}

		public boolean programClosed(Program closed) {
			if (this.program == closed) {
				this.program = null;
				this.staticRange = null;
				return true;
			}
			return false;
		}

		public Address getTraceAddress() {
			return mapping.getMinTraceAddress();
		}

		public Address getStaticAddress() {
			if (staticRange == null) {
				return null;
			}
			return staticRange.getMinAddress();
		}

		public TraceSpan getTraceSpan() {
			return new DefaultTraceSpan(mapping.getTrace(), mapping.getLifespan());
		}

		public TraceAddressSnapRange getTraceAddressSnapRange() {
			// NOTE: No need to capture shape since static mappings are immutable
			return new ImmutableTraceAddressSnapRange(mapping.getTraceAddressRange(),
				mapping.getLifespan());
		}

		public boolean isInTraceRange(Address address, Long snap) {
			return mapping.getTraceAddressRange().contains(address) &&
				(snap == null || mapping.getLifespan().contains(snap));
		}

		public boolean isInTraceRange(AddressRange rng, Long snap) {
			return mapping.getTraceAddressRange().intersects(rng) &&
				(snap == null || mapping.getLifespan().contains(snap));
		}

		public boolean isInTraceLifespan(long snap) {
			return mapping.getLifespan().contains(snap);
		}

		public boolean isInProgramRange(Address address) {
			if (staticRange == null) {
				return false;
			}
			return staticRange.contains(address);
		}

		public boolean isInProgramRange(AddressRange rng) {
			if (staticRange == null) {
				return false;
			}
			return staticRange.intersects(rng);
		}

		protected Address mapTraceAddressToProgram(Address address) {
			assert isInTraceRange(address, null);
			long offset = address.subtract(mapping.getMinTraceAddress());
			return staticRange.getMinAddress().addWrapSpace(offset);
		}

		public ProgramLocation mapTraceAddressToProgramLocation(Address address) {
			if (program == null) {
				throw new IllegalStateException("Static program is not opened");
			}
			return new ProgramLocation(program, mapTraceAddressToProgram(address));
		}

		public AddressRange mapTraceRangeToProgram(AddressRange rng) {
			assert isInTraceRange(rng, null);
			AddressRange part = rng.intersect(mapping.getTraceAddressRange());
			Address min = mapTraceAddressToProgram(part.getMinAddress());
			Address max = mapTraceAddressToProgram(part.getMaxAddress());
			return new AddressRangeImpl(min, max);
		}

		protected Address mapProgramAddressToTrace(Address address) {
			assert isInProgramRange(address);
			long offset = address.subtract(staticRange.getMinAddress());
			return mapping.getMinTraceAddress().addWrapSpace(offset);
		}

		protected TraceLocation mapProgramAddressToTraceLocation(Address address) {
			return new DefaultTraceLocation(mapping.getTrace(), null, mapping.getLifespan(),
				mapProgramAddressToTrace(address));
		}

		public AddressRange mapProgramRangeToTrace(AddressRange rng) {
			assert (rng.intersects(staticRange));
			AddressRange part = rng.intersect(staticRange);
			Address min = mapProgramAddressToTrace(part.getMinAddress());
			Address max = mapProgramAddressToTrace(part.getMaxAddress());
			return new AddressRangeImpl(min, max);
		}

		public boolean isStaticProgramOpen() {
			return program != null;
		}

		public URL getStaticProgramURL() {
			return mapping.getStaticProgramURL();
		}
	}

	protected class InfoPerTrace extends TraceDomainObjectListener {
		private Trace trace;
		private Map<TraceAddressSnapRange, MappingEntry> outbound = new HashMap<>();

		public InfoPerTrace(Trace trace) {
			this.trace = trace;

			listenForUntyped(DomainObject.DO_OBJECT_RESTORED, e -> objectRestored());
			listenFor(TraceStaticMappingChangeType.ADDED, this::staticMappingAdded);
			listenFor(TraceStaticMappingChangeType.DELETED, this::staticMappingDeleted);

			trace.addListener(this);

			loadOutboundEntries();
		}

		private void objectRestored() {
			synchronized (lock) {
				doAffectedByTraceClosed(trace);
				outbound.clear();
				loadOutboundEntries(); // Also places/updates corresponding inbound entries
				// TODO: What about removed corresponding inbound entries?
				doAffectedByTraceOpened(trace);
			}
		}

		private void staticMappingAdded(TraceStaticMapping mapping) {
			// Msg.debug(this, "Trace Mapping added: " + mapping);
			synchronized (lock) {
				MappingEntry me = new MappingEntry(mapping);
				putOutboundAndInboundEntries(me);
				if (me.program != null) {
					traceAffected(trace);
					programAffected(me.program);
				}
			}
		}

		private void staticMappingDeleted(TraceStaticMapping mapping) {
			synchronized (lock) {
				MappingEntry me =
					outbound.get(new ImmutableTraceAddressSnapRange(mapping.getTraceAddressRange(),
						mapping.getLifespan()));
				if (me == null) {
					Msg.warn(this, "It appears I lost track of something that just got removed");
					return;
				}
				Program program = me.program;
				removeOutboundAndInboundEntries(me);
				if (program != null) {
					traceAffected(trace);
					programAffected(program);
				}
			}
		}

		public void dispose() {
			trace.removeListener(this);
		}

		protected void putOutboundAndInboundEntries(MappingEntry me) {
			outbound.put(me.getTraceAddressSnapRange(), me);

			InfoPerProgram destInfo = trackedProgramInfo.get(me.getStaticProgramURL());
			if (destInfo == null) {
				return; // Not opened
			}
			me.programOpened(destInfo.program);
			destInfo.inbound.put(me, me.getStaticAddress());
		}

		protected void removeOutboundAndInboundEntries(MappingEntry me) {
			outbound.remove(me.getTraceAddressSnapRange());

			InfoPerProgram destInfo = trackedProgramInfo.get(me.getStaticProgramURL());
			if (destInfo == null) {
				return; // Not opened
			}
			destInfo.inbound.remove(me);
		}

		protected void loadOutboundEntries() {
			TraceStaticMappingManager manager = trace.getStaticMappingManager();
			for (TraceStaticMapping mapping : manager.getAllEntries()) {
				putOutboundAndInboundEntries(new MappingEntry(mapping));
			}
		}

		public boolean programOpened(Program other, InfoPerProgram otherInfo) {
			boolean result = false;
			for (MappingEntry me : outbound.values()) {
				if (me.programOpened(other)) {
					otherInfo.inbound.put(me, me.getStaticAddress());
					result = true;
				}
			}
			return result;
		}

		public boolean programClosed(Program other) {
			boolean result = false;
			for (MappingEntry me : outbound.values()) {
				result |= me.programClosed(other);
			}
			return result;
		}

		public Set<Program> getOpenMappedProgramsAtSnap(long snap) {
			Set<Program> result = new HashSet<>();
			for (Entry<TraceAddressSnapRange, MappingEntry> out : outbound.entrySet()) {
				MappingEntry me = out.getValue();
				if (!me.isStaticProgramOpen()) {
					continue;
				}
				if (!out.getKey().getLifespan().contains(snap)) {
					continue;
				}
				result.add(me.program);
			}
			return result;
		}

		public ProgramLocation getOpenMappedLocations(Address address, Lifespan span) {
			TraceAddressSnapRange at = new ImmutableTraceAddressSnapRange(address, span);
			for (Entry<TraceAddressSnapRange, MappingEntry> out : outbound.entrySet()) {
				if (out.getKey().intersects(at)) {
					MappingEntry me = out.getValue();
					if (me.isStaticProgramOpen()) {
						return me.mapTraceAddressToProgramLocation(address);
					}
				}
			}
			return null;
		}

		protected void collectOpenMappedPrograms(AddressRange rng, Lifespan span,
				Map<Program, Collection<MappedAddressRange>> result) {
			TraceAddressSnapRange tatr = new ImmutableTraceAddressSnapRange(rng, span);
			for (Entry<TraceAddressSnapRange, MappingEntry> out : outbound.entrySet()) {
				MappingEntry me = out.getValue();
				if (me.program == null) {
					continue;
				}
				if (!out.getKey().intersects(tatr)) {
					continue;
				}
				AddressRange srcRng = out.getKey().getRange().intersect(rng);
				AddressRange dstRng = me.mapTraceRangeToProgram(rng);
				result.computeIfAbsent(me.program, p -> new TreeSet<>())
						.add(new MappedAddressRange(srcRng, dstRng));
			}
		}

		public Map<Program, Collection<MappedAddressRange>> getOpenMappedViews(AddressSetView set,
				Lifespan span) {
			Map<Program, Collection<MappedAddressRange>> result = new HashMap<>();
			for (AddressRange rng : set) {
				collectOpenMappedPrograms(rng, span, result);
			}
			return Collections.unmodifiableMap(result);
		}

		protected void collectMappedProgramURLsInView(AddressRange rng, Lifespan span,
				Set<URL> result) {
			TraceAddressSnapRange tatr = new ImmutableTraceAddressSnapRange(rng, span);
			for (Entry<TraceAddressSnapRange, MappingEntry> out : outbound.entrySet()) {
				if (!out.getKey().intersects(tatr)) {
					continue;
				}
				MappingEntry me = out.getValue();
				result.add(me.getStaticProgramURL());
			}
		}

		public Set<URL> getMappedProgramURLsInView(AddressSetView set, Lifespan span) {
			Set<URL> result = new HashSet<>();
			for (AddressRange rng : set) {
				collectMappedProgramURLsInView(rng, span, result);
			}
			return Collections.unmodifiableSet(result);
		}
	}

	protected class InfoPerProgram implements DomainObjectListener {
		private Program program;

		private ValueSortedMap<MappingEntry, Address> inbound =
			TreeValueSortedMap.createWithNaturalOrder();

		public InfoPerProgram(Program program) {
			this.program = program;
			program.addListener(this);
			loadInboundEntries();
		}

		@Override
		public void domainObjectChanged(DomainObjectChangedEvent ev) {
			if (ev.containsEvent(DomainObject.DO_DOMAIN_FILE_CHANGED)) {
				// TODO: This seems like overkill
				programClosed(program);
				programOpened(program);
			}
			// TODO: Can I listen for when the program moves?
			// TODO: Or when relevant blocks move?
		}

		protected void loadInboundEntries() {
			for (InfoPerTrace traceInfo : trackedTraceInfo.values()) {
				for (MappingEntry out : traceInfo.outbound.values()) {
					if (out.program == program) {
						inbound.put(out, out.getStaticAddress());
					}
				}
			}
		}

		public boolean isMappedInTrace(Trace trace) {
			for (MappingEntry me : inbound.keySet()) {
				if (Objects.equals(trace, me.getTrace())) {
					return true;
				}
			}
			return false;
		}

		public boolean traceClosed(Trace trace) {
			Set<MappingEntry> updates = new HashSet<>();
			for (Entry<MappingEntry, Address> ent : inbound.entrySet()) {
				MappingEntry me = ent.getKey();
				if (Objects.equals(trace, me.getTrace())) {
					updates.add(me);
				}
			}
			return inbound.keySet().removeAll(updates);
		}

		public Set<TraceLocation> getOpenMappedTraceLocations(Address address) {
			Set<TraceLocation> result = new HashSet<>();
			for (Entry<MappingEntry, Address> inPreceding : inbound.headMapByValue(address,
				true).entrySet()) {
				Address start = inPreceding.getValue();
				if (start == null) {
					continue;
				}
				MappingEntry me = inPreceding.getKey();
				if (!me.isInProgramRange(address)) {
					continue;
				}
				result.add(me.mapProgramAddressToTraceLocation(address));
			}
			return result;
		}

		public TraceLocation getOpenMappedTraceLocation(Trace trace, Address address, long snap) {
			// TODO: Map by trace?
			for (Entry<MappingEntry, Address> inPreceding : inbound.headMapByValue(address,
				true).entrySet()) {
				Address start = inPreceding.getValue();
				if (start == null) {
					continue;
				}
				MappingEntry me = inPreceding.getKey();
				if (me.getTrace() != trace) {
					continue;
				}
				if (!me.isInProgramRange(address)) {
					continue;
				}
				if (!me.isInTraceLifespan(snap)) {
					continue;
				}
				return me.mapProgramAddressToTraceLocation(address);
			}
			return null;
		}

		protected void collectOpenMappedViews(AddressRange rng,
				Map<TraceSpan, Collection<MappedAddressRange>> result) {
			for (Entry<MappingEntry, Address> inPreceeding : inbound.headMapByValue(
				rng.getMaxAddress(), true).entrySet()) {
				Address start = inPreceeding.getValue();
				if (start == null) {
					continue;
				}
				MappingEntry me = inPreceeding.getKey();
				if (!me.isInProgramRange(rng)) {
					continue;
				}

				AddressRange srcRange = me.staticRange.intersect(rng);
				AddressRange dstRange = me.mapProgramRangeToTrace(rng);
				result.computeIfAbsent(me.getTraceSpan(), p -> new TreeSet<>())
						.add(new MappedAddressRange(srcRange, dstRange));
			}
		}

		public Map<TraceSpan, Collection<MappedAddressRange>> getOpenMappedViews(
				AddressSetView set) {
			Map<TraceSpan, Collection<MappedAddressRange>> result = new HashMap<>();
			for (AddressRange rng : set) {
				collectOpenMappedViews(rng, result);
			}
			return Collections.unmodifiableMap(result);
		}
	}

	private final Map<Trace, InfoPerTrace> trackedTraceInfo = new HashMap<>();
	private final Map<URL, InfoPerProgram> trackedProgramInfo = new HashMap<>();

	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed
	private ProgramManager programManager;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoWiring;

	private final Object lock = new Object();

	private final AsyncDebouncer<Void> changeDebouncer =
		new AsyncDebouncer<>(AsyncTimer.DEFAULT_TIMER, 100);
	private final ListenerSet<DebuggerStaticMappingChangeListener> changeListeners =
		new ListenerSet<>(DebuggerStaticMappingChangeListener.class);
	private Set<Trace> affectedTraces = new HashSet<>();
	private Set<Program> affectedPrograms = new HashSet<>();

	private final ProgramModuleIndexer programModuleIndexer;
	private final ModuleMapProposalGenerator moduleMapProposalGenerator;

	public DebuggerStaticMappingServicePlugin(PluginTool tool) {
		super(tool);
		this.autoWiring = AutoService.wireServicesProvidedAndConsumed(this);
		this.programModuleIndexer = new ProgramModuleIndexer(tool);
		this.moduleMapProposalGenerator = new ModuleMapProposalGenerator(programModuleIndexer);

		changeDebouncer.addListener(this::fireChangeListeners);
		tool.getProject().getProjectData().addDomainFolderChangeListener(this);
	}

	@Override
	protected void dispose() {
		tool.getProject().getProjectData().removeDomainFolderChangeListener(this);
		super.dispose();
	}

	private void fireChangeListeners(Void v) {
		Set<Trace> traces;
		Set<Program> programs;
		synchronized (affectedTraces) {
			traces = Collections.unmodifiableSet(affectedTraces);
			programs = Collections.unmodifiableSet(affectedPrograms);
			affectedTraces = new HashSet<>();
			affectedPrograms = new HashSet<>();
		}
		changeListeners.fire.mappingsChanged(traces, programs);
	}

	private void traceAffected(Trace trace) {
		synchronized (affectedTraces) {
			affectedTraces.add(trace);
			changeDebouncer.contact(null);
		}
	}

	private void programAffected(Program program) {
		synchronized (affectedTraces) {
			affectedPrograms.add(program);
			changeDebouncer.contact(null);
		}
	}

	@Override
	public void addChangeListener(DebuggerStaticMappingChangeListener l) {
		changeListeners.add(l);
	}

	@Override
	public void removeChangeListener(DebuggerStaticMappingChangeListener l) {
		changeListeners.remove(l);
	}

	@Override
	public CompletableFuture<Void> changesSettled() {
		return changeDebouncer.stable();
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramOpenedPluginEvent) {
			ProgramOpenedPluginEvent openedEvt = (ProgramOpenedPluginEvent) event;
			programOpened(openedEvt.getProgram());
		}
		else if (event instanceof ProgramClosedPluginEvent) {
			ProgramClosedPluginEvent closedEvt = (ProgramClosedPluginEvent) event;
			programClosed(closedEvt.getProgram());
		}
		else if (event instanceof TraceOpenedPluginEvent) {
			TraceOpenedPluginEvent openedEvt = (TraceOpenedPluginEvent) event;
			traceOpened(openedEvt.getTrace());
		}
		else if (event instanceof TraceClosedPluginEvent) {
			TraceClosedPluginEvent closedEvt = (TraceClosedPluginEvent) event;
			traceClosed(closedEvt.getTrace());
		}
	}

	private void programOpened(Program program) {
		synchronized (lock) {
			if (program instanceof TraceProgramView) {
				return; // TODO: Allow this?
			}
			URL url = ProgramURLUtils.getUrlFromProgram(program);
			if (url == null) {
				// Not in a project. Nothing could refer to it anyway....
				// TODO: If the program is saved into a project, it could be....
				return;
			}
			InfoPerProgram newInfo = new InfoPerProgram(program);
			InfoPerProgram mustBeNull = trackedProgramInfo.put(url, newInfo);
			assert mustBeNull == null;

			for (InfoPerTrace info : trackedTraceInfo.values()) {
				if (info.programOpened(program, newInfo)) {
					programAffected(program);
					traceAffected(info.trace);
				}
			}
		}
	}

	private void programClosed(Program program) {
		synchronized (lock) {
			if (program instanceof TraceProgramView) {
				return;
			}
			// NB. The URL may have changed, so can't use that as key
			for (Iterator<InfoPerProgram> it =
				trackedProgramInfo.values().iterator(); it.hasNext();) {
				InfoPerProgram info = it.next();
				if (info.program == program) {
					it.remove();
				}
			}
			for (InfoPerTrace info : trackedTraceInfo.values()) {
				if (info.programClosed(program)) {
					traceAffected(info.trace);
				}
			}
		}
	}

	@Override
	public void domainFileObjectOpenedForUpdate(DomainFile file, DomainObject object) {
		// This get called when a domain object is saved into the active project
		// We essentially need to update the URL, which requires examining every entry
		// TODO: Could probably cut out a bit of the kruft, but this should do
		if (object instanceof Program) {
			Program program = (Program) object;
			synchronized (lock) {
				programClosed(program);
				int i = ArrayUtils.indexOf(programManager.getAllOpenPrograms(), program);
				if (i >= 0) {
					programOpened(program);
				}
			}
		}
	}

	private void doAffectedByTraceOpened(Trace trace) {
		for (InfoPerProgram info : trackedProgramInfo.values()) {
			if (info.isMappedInTrace(trace)) {
				traceAffected(trace);
				programAffected(info.program);
			}
		}
	}

	private void traceOpened(Trace trace) {
		synchronized (lock) {
			if (trace.isClosed()) {
				Msg.warn(this, "Got traceOpened for a close trace");
				return;
			}
			InfoPerTrace newInfo = new InfoPerTrace(trace);
			InfoPerTrace mustBeNull = trackedTraceInfo.put(trace, newInfo);
			assert mustBeNull == null;
			doAffectedByTraceOpened(trace);
		}
	}

	private void doAffectedByTraceClosed(Trace trace) {
		for (InfoPerProgram info : trackedProgramInfo.values()) {
			if (info.traceClosed(trace)) {
				programAffected(info.program);
			}
		}
	}

	private void traceClosed(Trace trace) {
		synchronized (lock) {
			InfoPerTrace traceInfo = trackedTraceInfo.remove(trace);
			if (traceInfo == null) {
				Msg.warn(this, "Got traceClosed without/before traceOpened");
				return;
			}
			traceInfo.dispose();
			doAffectedByTraceClosed(trace);
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
			try (Transaction tx =
				ent.getKey().openTransaction("Memorize module mapping")) {
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
		Msg.warn(this, "The given trace is not open in this tool " +
			"(or the service hasn't received and processed the open-trace event, yet)");
		return null;
	}

	protected <T> T noProgramInfo() {
		Msg.warn(this, "The given program is not open in this tool " +
			"(or the service hasn't received and processed the open-program event, yet)");
		return null;
	}

	protected <T> T noProject() {
		return DebuggerStaticMappingUtils.noProject(this);
	}

	protected InfoPerTrace requireTrackedInfo(Trace trace) {
		InfoPerTrace info = trackedTraceInfo.get(trace);
		if (info == null) {
			return noTraceInfo();
		}
		return info;
	}

	protected InfoPerProgram requireTrackedInfo(Program program) {
		URL url = ProgramURLUtils.getUrlFromProgram(program);
		if (url == null) {
			return noProject();
		}
		InfoPerProgram info = trackedProgramInfo.get(url);
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
			return info.getOpenMappedLocations(loc.getAddress(), loc.getLifespan());
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
				return null;
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
			urls = info.getMappedProgramURLsInView(set, Lifespan.at(snap));
		}
		Set<Program> result = new HashSet<>();
		for (URL url : urls) {
			try {
				Program program = ProgramURLUtils.openHackedUpGhidraURL(programManager,
					tool.getProject(), url, ProgramManager.OPEN_VISIBLE);
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
