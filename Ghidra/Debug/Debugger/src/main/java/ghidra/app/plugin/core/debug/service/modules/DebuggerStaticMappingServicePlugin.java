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

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import org.apache.commons.lang3.ArrayUtils;

import com.google.common.collect.Range;

import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.events.ProgramOpenedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent;
import ghidra.app.plugin.core.debug.event.TraceOpenedPluginEvent;
import ghidra.app.plugin.core.debug.utils.*;
import ghidra.app.services.*;
import ghidra.async.AsyncDebouncer;
import ghidra.async.AsyncTimer;
import ghidra.framework.data.OpenedDomainFile;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.store.FileSystem;
import ghidra.generic.util.datastruct.TreeValueSortedMap;
import ghidra.generic.util.datastruct.ValueSortedMap;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.model.*;
import ghidra.trace.model.Trace.TraceStaticMappingChangeType;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.modules.*;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.Msg;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.datastruct.ListenerSet;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

@PluginInfo( //
	shortDescription = "Debugger static mapping manager", //
	description = "Track and manage static mappings (program-trace relocations)", //
	category = PluginCategoryNames.DEBUGGER, //
	packageName = DebuggerPluginPackage.NAME, //
	status = PluginStatus.RELEASED, //
	eventsConsumed = {
		ProgramOpenedPluginEvent.class, //
		ProgramClosedPluginEvent.class, //
		TraceOpenedPluginEvent.class, // 
		TraceClosedPluginEvent.class, //
	}, //
	servicesRequired = { //
		ProgramManager.class, //
		DebuggerTraceManagerService.class, //
	}, //
	servicesProvided = { //
		DebuggerStaticMappingService.class, //
	} // 
)
public class DebuggerStaticMappingServicePlugin extends Plugin
		implements DebuggerStaticMappingService, DomainFolderChangeAdapter {

	protected static class PluginModuleMapProposal implements ModuleMapProposal {
		private final TraceModule module;
		private final Program program;

		private final NavigableMap<Long, RegionMatcher> matchers = new TreeMap<>();
		private Address imageBase;
		private Address moduleBase;
		private long imageSize;
		private AddressRange moduleRange; // TODO: This is now in the trace schema. Use it.

		public PluginModuleMapProposal(TraceModule module, Program program) {
			this.module = module;
			this.program = program;
			processProgram();
			processModule();
		}

		@Override
		public TraceModule getModule() {
			return module;
		}

		@Override
		public Program getProgram() {
			return program;
		}

		private RegionMatcher getMatcher(long baseOffset) {
			return matchers.computeIfAbsent(baseOffset, RegionMatcher::new);
		}

		private void processProgram() {
			imageBase = program.getImageBase();
			imageSize = ModuleMapEntry.computeImageSize(program);
			// TODO: How to handle Harvard architectures?
			for (MemoryBlock block : program.getMemory().getBlocks()) {
				if (!ModuleMapEntry.includeBlock(program, block)) {
					continue;
				}
				getMatcher(block.getStart().subtract(imageBase)).block = block;
			}
		}

		/**
		 * Must be called after processProgram, so that image size is known
		 */
		private void processModule() {
			moduleBase = module.getBase();
			try {
				moduleRange = new AddressRangeImpl(moduleBase, imageSize);
			}
			catch (AddressOverflowException e) {
				return; // Just score it as having no matches?
			}
			for (TraceMemoryRegion region : module.getTrace()
					.getMemoryManager()
					.getRegionsIntersecting(module.getLifespan(), moduleRange)) {
				getMatcher(region.getMinAddress().subtract(moduleBase)).region = region;
			}
		}

		@Override
		public double computeScore() {
			return ((double) matchers.values()
					.stream()
					.reduce(0, (s, m) -> s + m.score(), Integer::sum)) /
				matchers.size();
		}

		@Override
		public Map<TraceModule, ModuleMapEntry> computeMap() {
			return Map.of(module, new ModuleMapEntry(module, program, moduleRange));
		}
	}

	protected static class RegionMatcher {
		private MemoryBlock block;
		private TraceMemoryRegion region;

		public RegionMatcher(long baseOffset) {
		}

		private int score() {
			if (block == null || region == null) {
				return 0; // Unmatched
			}
			int score = 3; // For the matching offset
			if (block.getSize() == region.getLength()) {
				score += 10;
			}
			return score;
		}
	}

	protected static class PluginSectionMapProposal implements SectionMapProposal {
		private final TraceModule module;
		private final Program program;
		private final Map<String, SectionMatcher> matchers = new LinkedHashMap<>();

		public PluginSectionMapProposal(TraceModule module, Program program) {
			this.module = module;
			this.program = program;
			processModule();
			processProgram();
		}

		public PluginSectionMapProposal(TraceSection section, Program program, MemoryBlock block) {
			this.module = section.getModule();
			this.program = program;
			processSection(section);
			processBlock(block);
		}

		@Override
		public TraceModule getModule() {
			return module;
		}

		@Override
		public Program getProgram() {
			return program;
		}

		private void processSection(TraceSection section) {
			matchers.put(section.getName(), new SectionMatcher(section));
		}

		private void processBlock(MemoryBlock block) {
			SectionMatcher m =
				matchers.computeIfAbsent(block.getName(), n -> new SectionMatcher(null));
			m.block = block;
		}

		private void processModule() {
			for (TraceSection section : module.getSections()) {
				processSection(section);
			}
		}

		private void processProgram() {
			for (MemoryBlock block : program.getMemory().getBlocks()) {
				processBlock(block);
			}
		}

		@Override
		public double computeScore() {
			return ((double) matchers.values()
					.stream()
					.reduce(0, (s, m) -> s + m.score(), Integer::sum)) /
				matchers.size();
		}

		@Override
		public Map<TraceSection, SectionMapEntry> computeMap() {
			return matchers.values()
					.stream()
					.filter(m -> m.section != null && m.block != null)
					.collect(Collectors.toMap(m -> m.section,
						m -> new SectionMapEntry(m.section, program, m.block)));
		}

		@Override
		public MemoryBlock getDestination(TraceSection section) {
			SectionMatcher m = matchers.get(section.getName());
			return m == null ? null : m.block;
		}
	}

	protected static class SectionMatcher {
		private final TraceSection section;
		private MemoryBlock block;

		public SectionMatcher(TraceSection section) {
			this.section = section;
		}

		public int score() {
			if (section == null || block == null) {
				return 0; // Unmatched
			}
			int score = 3; // For the matching name
			if (section.getRange().getLength() == block.getSize()) {
				score += 10;
			}
			if ((section.getStart().getOffset() & 0xfff) == (block.getStart().getOffset() &
				0xfff)) {
				score += 20;
			}
			return score;
		}
	}

	protected class MappingEntry {
		private final TraceStaticMapping mapping;

		private Program program;
		private AddressRange staticRange;
		private Long shift; // from static image to trace

		public MappingEntry(TraceStaticMapping mapping) {
			this.mapping = mapping;
		}

		public Trace getTrace() {
			return mapping.getTrace();
		}

		public Address addOrMax(Address start, long length) {
			try {
				return start.addNoWrap(length);
			}
			catch (AddressOverflowException e) {
				Msg.warn(this, "Mapping entry cause overflow in static address space");
				return start.getAddressSpace().getMaxAddress();
			}
		}

		public boolean programOpened(Program opened) {
			if (mapping.getStaticProgramURL().equals(ProgramURLUtils.getUrlFromProgram(opened))) {
				this.program = opened;
				Address minAddr = opened.getAddressFactory().getAddress(mapping.getStaticAddress());
				Address maxAddr = addOrMax(minAddr, mapping.getLength() - 1);
				this.staticRange = new AddressRangeImpl(minAddr, maxAddr);
				this.shift = mapping.getMinTraceAddress().getOffset() -
					staticRange.getMinAddress().getOffset();
				return true;
			}
			return false;
		}

		public boolean programClosed(Program closed) {
			if (this.program == closed) {
				this.program = null;
				this.staticRange = null;
				this.shift = null;
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

		public TraceSnap getTraceSnap() {
			return new DefaultTraceSnap(mapping.getTrace(), mapping.getStartSnap());
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
			return staticRange.getMinAddress().add(offset);
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
			return mapping.getMinTraceAddress().add(offset);
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

		public Program openStaticProgram() {
			return ProgramURLUtils.openHackedUpGhidraURL(programManager, tool.getProject(),
				mapping.getStaticProgramURL(), ProgramManager.OPEN_VISIBLE);
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

		public ProgramLocation getOpenMappedLocations(Address address, Range<Long> span) {
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

		protected void collectOpenMappedPrograms(AddressRange rng, Range<Long> span,
				Map<Program, ShiftAndAddressSetView> result) {
			TraceAddressSnapRange tatr = new ImmutableTraceAddressSnapRange(rng, span);
			for (Entry<TraceAddressSnapRange, MappingEntry> out : outbound.entrySet()) {
				MappingEntry me = out.getValue();
				if (me.program == null) {
					continue;
				}
				if (!out.getKey().intersects(tatr)) {
					continue;
				}

				ShiftAndAddressSetView set = result.computeIfAbsent(me.program,
					p -> new ShiftAndAddressSetView(-me.shift, new AddressSet()));
				((AddressSet) set.getAddressSetView()).add(me.mapTraceRangeToProgram(rng));
			}
		}

		public Map<Program, ShiftAndAddressSetView> getOpenMappedViews(AddressSetView set,
				Range<Long> span) {
			Map<Program, ShiftAndAddressSetView> result = new HashMap<>();
			for (AddressRange rng : set) {
				collectOpenMappedPrograms(rng, span, result);
			}
			return Collections.unmodifiableMap(result);
		}

		protected void openAndCollectPrograms(AddressRange rng, Range<Long> span,
				Set<Program> result, Set<Exception> failures) {
			TraceAddressSnapRange tatr = new ImmutableTraceAddressSnapRange(rng, span);
			for (Entry<TraceAddressSnapRange, MappingEntry> out : outbound.entrySet()) {
				if (!out.getKey().intersects(tatr)) {
					continue;
				}
				MappingEntry me = out.getValue();
				try {
					result.add(me.openStaticProgram());
				}
				catch (Exception e) {
					if (failures == null) {
						throw e;
					}
					failures.add(e);
				}
			}
		}

		public Set<Program> openMappedProgramsInView(AddressSetView set, Range<Long> span,
				Set<Exception> failures) {
			Set<Program> result = new HashSet<>();
			for (AddressRange rng : set) {
				openAndCollectPrograms(rng, span, result, failures);
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
				Map<TraceSnap, ShiftAndAddressSetView> result) {
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
				ShiftAndAddressSetView set = result.computeIfAbsent(me.getTraceSnap(),
					p -> new ShiftAndAddressSetView(me.shift, new AddressSet()));
				((AddressSet) set.getAddressSetView()).add(me.mapProgramRangeToTrace(rng));
			}
		}

		public Map<TraceSnap, ShiftAndAddressSetView> getOpenMappedViews(AddressSetView set) {
			Map<TraceSnap, ShiftAndAddressSetView> result = new HashMap<>();
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

	public DebuggerStaticMappingServicePlugin(PluginTool tool) {
		super(tool);
		this.autoWiring = AutoService.wireServicesProvidedAndConsumed(this);

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
		Program tp = to.getProgram();
		if (tp instanceof TraceProgramView) {
			throw new IllegalArgumentException(
				"Mapping destination cannot be a " + TraceProgramView.class.getSimpleName());
		}
		TraceStaticMappingManager manager = from.getTrace().getStaticMappingManager();
		URL toURL = ProgramURLUtils.getUrlFromProgram(tp);
		if (toURL == null) {
			noProject();
		}
		Address fromAddress = from.getAddress();
		Address toAddress = to.getByteAddress();
		long maxFromLengthMinus1 =
			fromAddress.getAddressSpace().getMaxAddress().subtract(fromAddress);
		long maxToLengthMinus1 =
			toAddress.getAddressSpace().getMaxAddress().subtract(toAddress);
		if (Long.compareUnsigned(length - 1, maxFromLengthMinus1) > 0) {
			throw new IllegalArgumentException("Length would cause address overflow in trace");
		}
		if (Long.compareUnsigned(length - 1, maxToLengthMinus1) > 0) {
			throw new IllegalArgumentException("Length would cause address overflow in program");
		}
		Address end = fromAddress.addWrap(length - 1);
		// Also check end in the destination
		AddressRangeImpl range = new AddressRangeImpl(fromAddress, end);
		Range<Long> fromLifespan = from.getLifespan();
		if (truncateExisting) {
			long truncEnd = DBTraceUtils.lowerEndpoint(fromLifespan) - 1;
			for (TraceStaticMapping existing : List
					.copyOf(manager.findAllOverlapping(range, fromLifespan))) {
				existing.delete();
				if (fromLifespan.hasLowerBound() &&
					Long.compare(existing.getStartSnap(), truncEnd) <= 0) {
					manager.add(existing.getTraceAddressRange(),
						Range.closed(existing.getStartSnap(), truncEnd),
						existing.getStaticProgramURL(), existing.getStaticAddress());
				}
			}
		}
		manager.add(range, fromLifespan, toURL, toAddress.toString(true));
	}

	@Override
	public void addModuleMapping(TraceModule from, long length, Program toProgram,
			boolean truncateExisting) throws TraceConflictedMappingException {
		TraceLocation fromLoc =
			new DefaultTraceLocation(from.getTrace(), null, from.getLifespan(), from.getBase());
		ProgramLocation toLoc = new ProgramLocation(toProgram, toProgram.getImageBase());
		addMapping(fromLoc, toLoc, length, truncateExisting);
	}

	@Override
	public void addModuleMappings(Collection<ModuleMapEntry> entries, TaskMonitor monitor,
			boolean truncateExisting) throws CancelledException {
		Map<Trace, Set<ModuleMapEntry>> byTrace = new LinkedHashMap<>();
		for (ModuleMapEntry ent : entries) {
			Set<ModuleMapEntry> subCol =
				byTrace.computeIfAbsent(ent.getModule().getTrace(), t -> new LinkedHashSet<>());
			subCol.add(ent);
		}
		for (Map.Entry<Trace, Set<ModuleMapEntry>> ent : byTrace.entrySet()) {
			Trace trace = ent.getKey();
			try (UndoableTransaction tid =
				UndoableTransaction.start(trace, "Add module mappings", false)) {
				doAddModuleMappings(trace, ent.getValue(), monitor, truncateExisting);
				tid.commit();
			}
		}
	}

	protected void doAddModuleMappings(Trace trace, Collection<ModuleMapEntry> entries,
			TaskMonitor monitor, boolean truncateExisting) throws CancelledException {
		for (ModuleMapEntry ent : entries) {
			monitor.checkCanceled();
			try {
				addModuleMapping(ent.getModule(), ent.getModuleRange().getLength(),
					ent.getProgram(), truncateExisting);
			}
			catch (Exception e) {
				Msg.error(this, "Could not add mapping " + ent + ": " + e.getMessage());
			}
		}
	}

	@Override
	public void addSectionMapping(TraceSection from, Program toProgram, MemoryBlock to,
			boolean truncateExisting) throws TraceConflictedMappingException {
		TraceLocation fromLoc = new DefaultTraceLocation(from.getTrace(), null,
			from.getModule().getLifespan(), from.getStart());
		ProgramLocation toLoc = new ProgramLocation(toProgram, to.getStart());
		long length = Math.min(from.getRange().getLength(), to.getSize());
		addMapping(fromLoc, toLoc, length, truncateExisting);
	}

	@Override
	public void addSectionMappings(Collection<SectionMapEntry> entries,
			TaskMonitor monitor, boolean truncateExisting) throws CancelledException {
		Map<Trace, Set<SectionMapEntry>> byTrace = new LinkedHashMap<>();
		for (SectionMapEntry ent : entries) {
			Set<SectionMapEntry> subCol =
				byTrace.computeIfAbsent(ent.getSection().getTrace(), t -> new LinkedHashSet<>());
			subCol.add(ent);
		}
		for (Map.Entry<Trace, Set<SectionMapEntry>> ent : byTrace.entrySet()) {
			Trace trace = ent.getKey();
			try (UndoableTransaction tid =
				UndoableTransaction.start(trace, "Add section mappings", false)) {
				doAddSectionMappings(trace, ent.getValue(), monitor, truncateExisting);
				tid.commit();
			}
		}
	}

	protected void doAddSectionMappings(Trace trace, Collection<SectionMapEntry> entries,
			TaskMonitor monitor, boolean truncateExisting) throws CancelledException {
		for (SectionMapEntry ent : entries) {
			monitor.checkCanceled();
			try {
				addSectionMapping(ent.getSection(), ent.getProgram(), ent.getBlock(),
					truncateExisting);
			}
			catch (Exception e) {
				Msg.error(this, "Could not add mapping " + ent + ": " + e.getMessage());
			}
		}
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
		Msg.warn(this, "The given program does not exist in any project");
		return null;
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
		InfoPerTrace info = requireTrackedInfo(trace);
		if (info == null) {
			return null;
		}
		return info.getOpenMappedProgramsAtSnap(snap);
	}

	@Override
	public ProgramLocation getOpenMappedLocation(TraceLocation loc) {
		InfoPerTrace info = requireTrackedInfo(loc.getTrace());
		if (info == null) {
			return null;
		}
		return info.getOpenMappedLocations(loc.getAddress(), loc.getLifespan());
	}

	protected long getNonScratchSnap(TraceProgramView view) {
		return view.getViewport().getTop(s -> s >= 0 ? s : null);
	}

	@Override
	public ProgramLocation getStaticLocationFromDynamic(ProgramLocation loc) {
		loc = ProgramLocationUtils.fixLocation(loc, true);
		TraceProgramView view = (TraceProgramView) loc.getProgram();
		Trace trace = view.getTrace();
		TraceLocation tloc = new DefaultTraceLocation(trace, null,
			Range.singleton(getNonScratchSnap(view)), loc.getByteAddress());
		ProgramLocation mapped = getOpenMappedLocation(tloc);
		if (mapped == null) {
			return null;
		}
		return ProgramLocationUtils.replaceAddress(loc, mapped.getProgram(),
			mapped.getByteAddress());
	}

	@Override
	public Set<TraceLocation> getOpenMappedLocations(ProgramLocation loc) {
		InfoPerProgram info = requireTrackedInfo(loc.getProgram());
		if (info == null) {
			return null;
		}
		return info.getOpenMappedTraceLocations(loc.getByteAddress());
	}

	@Override
	public TraceLocation getOpenMappedLocation(Trace trace, ProgramLocation loc, long snap) {
		InfoPerProgram info = requireTrackedInfo(loc.getProgram());
		if (info == null) {
			return null;
		}
		return info.getOpenMappedTraceLocation(trace, loc.getByteAddress(), snap);
	}

	@Override
	public ProgramLocation getDynamicLocationFromStatic(TraceProgramView view,
			ProgramLocation loc) {
		TraceLocation tloc = getOpenMappedLocation(view.getTrace(), loc, getNonScratchSnap(view));
		if (tloc == null) {
			return null;
		}
		return ProgramLocationUtils.replaceAddress(loc, view, tloc.getAddress());
	}

	@Override
	public Map<Program, ShiftAndAddressSetView> getOpenMappedViews(Trace trace,
			AddressSetView set,
			long snap) {
		InfoPerTrace info = requireTrackedInfo(trace);
		if (info == null) {
			return null;
		}
		return info.getOpenMappedViews(set, Range.singleton(snap));
	}

	@Override
	public Map<TraceSnap, ShiftAndAddressSetView> getOpenMappedViews(Program program,
			AddressSetView set) {
		InfoPerProgram info = requireTrackedInfo(program);
		if (info == null) {
			return null;
		}
		return info.getOpenMappedViews(set);
	}

	@Override
	public Set<Program> openMappedProgramsInView(Trace trace, AddressSetView set, long snap,
			Set<Exception> failures) {
		InfoPerTrace info = requireTrackedInfo(trace);
		if (info == null) {
			return null;
		}
		return info.openMappedProgramsInView(set, Range.singleton(snap), failures);
	}

	protected String normalizePath(String path) {
		path = path.replace('\\', FileSystem.SEPARATOR_CHAR);
		while (path.startsWith(FileSystem.SEPARATOR)) {
			path = path.substring(1);
		}
		return path;
	}

	protected DomainFile resolve(DomainFolder folder, String path) {
		StringBuilder fullPath = new StringBuilder(folder.getPathname());
		if (!fullPath.toString().endsWith(FileSystem.SEPARATOR)) {
			// Only root should end with /, anyway
			fullPath.append(FileSystem.SEPARATOR_CHAR);
		}
		fullPath.append(path);
		return folder.getProjectData().getFile(fullPath.toString());
	}

	public Set<DomainFile> doFindPrograms(String modulePath, DomainFolder folder) {
		// TODO: If not found, consider filenames with space + extra info
		while (folder != null) {
			DomainFile found = resolve(folder, modulePath);
			if (found != null) {
				return Set.of(found);
			}
			folder = folder.getParent();
		}
		return Set.of();
	}

	public Set<DomainFile> doFindProgramsByPathOrName(String modulePath, DomainFolder folder) {
		Set<DomainFile> found = doFindPrograms(modulePath, folder);
		if (!found.isEmpty()) {
			return found;
		}
		int idx = modulePath.lastIndexOf(FileSystem.SEPARATOR);
		if (idx == -1) {
			return Set.of();
		}
		found = doFindPrograms(modulePath.substring(idx + 1), folder);
		if (!found.isEmpty()) {
			return found;
		}
		return Set.of();
	}

	public Set<DomainFile> doFindProgramsByPathOrName(String modulePath, Project project) {
		return doFindProgramsByPathOrName(modulePath, project.getProjectData().getRootFolder());
	}

	@Override
	public Set<DomainFile> findProbableModulePrograms(TraceModule module) {
		// TODO: Consider folders containing existing mapping destinations
		DomainFile df = module.getTrace().getDomainFile();
		String modulePath = normalizePath(module.getName());
		if (df == null) {
			return doFindProgramsByPathOrName(modulePath, tool.getProject());
		}
		DomainFolder parent = df.getParent();
		if (parent == null) {
			return doFindProgramsByPathOrName(modulePath, tool.getProject());
		}
		return doFindProgramsByPathOrName(modulePath, parent);
	}

	protected void doCollectLibraries(ProjectData project, Program cur, Set<Program> col,
			TaskMonitor monitor) throws CancelledException {
		if (!col.add(cur)) {
			return;
		}
		ExternalManager externs = cur.getExternalManager();
		for (String extName : externs.getExternalLibraryNames()) {
			monitor.checkCanceled();
			Library lib = externs.getExternalLibrary(extName);
			String libPath = lib.getAssociatedProgramPath();
			if (libPath == null) {
				continue;
			}
			DomainFile libFile = project.getFile(libPath);
			if (libFile == null) {
				Msg.info(this, "Referenced external program not found: " + libPath);
				continue;
			}
			try (OpenedDomainFile<Program> program =
				OpenedDomainFile.open(Program.class, libFile, monitor)) {
				doCollectLibraries(project, program.content, col, monitor);
			}
			catch (ClassCastException e) {
				Msg.info(this,
					"Referenced external program is not a program: " + libPath + " is " +
						libFile.getDomainObjectClass());
				continue;
			}
			catch (VersionException | CancelledException | IOException e) {
				Msg.info(this, "Referenced external program could not be opened: " + e);
				continue;
			}
		}
	}

	@Override
	public Set<Program> collectLibraries(Program seed, TaskMonitor monitor)
			throws CancelledException {
		Set<Program> result = new LinkedHashSet<>();
		doCollectLibraries(seed.getDomainFile().getParent().getProjectData(), seed, result,
			monitor);
		return result;
	}

	@Override
	public PluginModuleMapProposal proposeModuleMap(TraceModule module, Program program) {
		return new PluginModuleMapProposal(module, program);
	}

	@Override
	public PluginModuleMapProposal proposeModuleMap(TraceModule module,
			Collection<? extends Program> programs) {
		double bestScore = -1;
		PluginModuleMapProposal bestMap = null;
		for (Program program : programs) {
			PluginModuleMapProposal map = proposeModuleMap(module, program);
			double score = map.computeScore();
			if (score == bestScore && programManager != null) {
				// Prefer the current program in ties
				if (programManager.getCurrentProgram() == program) {
					bestMap = map;
				}
			}
			if (score > bestScore) {
				bestScore = score;
				bestMap = map;
			}
		}
		return bestMap;
	}

	@Override
	public Map<TraceModule, ModuleMapProposal> proposeModuleMaps(
			Collection<? extends TraceModule> modules, Collection<? extends Program> programs) {
		Map<TraceModule, ModuleMapProposal> result = new LinkedHashMap<>();
		for (TraceModule module : modules) {
			String moduleName = getLastLower(module.getName());
			Set<Program> probable = programs.stream()
					.filter(p -> namesContain(p, moduleName))
					.collect(Collectors.toSet());
			PluginModuleMapProposal map = proposeModuleMap(module, probable);
			if (map == null) {
				continue;
			}
			result.put(module, map);
		}
		return result;
	}

	@Override
	public PluginSectionMapProposal proposeSectionMap(TraceSection section, Program program,
			MemoryBlock block) {
		return new PluginSectionMapProposal(section, program, block);
	}

	@Override
	public PluginSectionMapProposal proposeSectionMap(TraceModule module, Program program) {
		return new PluginSectionMapProposal(module, program);
	}

	@Override
	public PluginSectionMapProposal proposeSectionMap(TraceModule module,
			Collection<? extends Program> programs) {
		double bestScore = -1;
		PluginSectionMapProposal bestMap = null;
		for (Program program : programs) {
			PluginSectionMapProposal map = proposeSectionMap(module, program);
			double score = map.computeScore();
			if (score > bestScore) {
				bestScore = score;
				bestMap = map;
			}
		}
		return bestMap;
	}

	protected static String getLastLower(String path) {
		return new File(path).getName().toLowerCase();
	}

	/**
	 * Check if either the program's name, its executable path, or its domain file name contains the
	 * given module name
	 * 
	 * @param program the program whose names to check
	 * @param moduleLowerName the module name to check for in lower case
	 * @return true if matched, false if not
	 */
	protected boolean namesContain(Program program, String moduleLowerName) {
		DomainFile df = program.getDomainFile();
		if (df == null || df.getProjectLocator() == null) {
			return false;
		}
		String programName = getLastLower(program.getName());
		if (programName.contains(moduleLowerName)) {
			return true;
		}
		String exePath = program.getExecutablePath();
		if (exePath != null) {
			String execName = getLastLower(exePath);
			if (execName.contains(moduleLowerName)) {
				return true;
			}
		}
		String fileName = df.getName().toLowerCase();
		if (fileName.contains(moduleLowerName)) {
			return true;
		}
		return false;
	}

	@Override
	public Map<TraceModule, SectionMapProposal> proposeSectionMaps(
			Collection<? extends TraceModule> modules, Collection<? extends Program> programs) {
		Map<TraceModule, SectionMapProposal> result = new LinkedHashMap<>();
		for (TraceModule module : modules) {
			String moduleName = getLastLower(module.getName());
			Set<Program> probable = programs.stream()
					.filter(p -> namesContain(p, moduleName))
					.collect(Collectors.toSet());
			PluginSectionMapProposal map = proposeSectionMap(module, probable);
			if (map == null) {
				continue;
			}
			result.put(module, map);
		}
		return result;
	}
}
