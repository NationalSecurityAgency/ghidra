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

import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.HashSetValuedHashMap;

import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingServicePlugin.ChangeCollector;
import ghidra.app.services.DebuggerStaticMappingService.MappedAddressRange;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectEvent;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.modules.TraceStaticMapping;
import ghidra.trace.util.TraceEvents;
import ghidra.util.Msg;

class InfoPerTrace extends TraceDomainObjectListener {
	private final DebuggerStaticMappingServicePlugin plugin;
	final Trace trace;

	final Map<TraceStaticMapping, MappingEntry> outboundByEntry = new HashMap<>();
	final NavigableMap<TraceAddressSnapRange, MappingEntry> outboundByRange =
		new TreeMap<>(Comparator.comparing(TraceAddressSnapRange::getX1));
	final MultiValuedMap<URL, MappingEntry> outboundByStaticUrl = new HashSetValuedHashMap<>();

	private volatile boolean needsResync = false;

	InfoPerTrace(DebuggerStaticMappingServicePlugin plugin, Trace trace) {
		this.plugin = plugin;
		this.trace = trace;

		listenForUntyped(DomainObjectEvent.RESTORED, e -> objectRestored());
		listenFor(TraceEvents.MAPPING_ADDED, this::staticMappingAdded);
		listenFor(TraceEvents.MAPPING_DELETED, this::staticMappingDeleted);
		trace.addListener(this);
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		super.domainObjectChanged(ev); // Dispatch individual records
		// Now do the actual processing
		if (needsResync) {
			needsResync = false;
			CompletableFuture.runAsync(this::resyncEntries, plugin.executor);
		}
	}

	private void objectRestored() {
		this.needsResync = true;
	}

	private void staticMappingAdded(TraceStaticMapping mapping) {
		this.needsResync = true;
	}

	private void staticMappingDeleted(TraceStaticMapping mapping) {
		this.needsResync = true;
	}

	public void dispose() {
		trace.removeListener(this);
	}

	private void resyncEntries() {
		try (ChangeCollector cc = new ChangeCollector(plugin)) {
			// Invoke change callbacks without the lock! (try must surround sync)
			synchronized (plugin.lock) {
				resyncEntries(cc);
			}
		}
	}

	void resyncEntries(ChangeCollector cc) {
		Set<TraceStaticMapping> oldEntries = outboundByEntry.keySet();
		Set<TraceStaticMapping> curEntries = trace.getStaticMappingManager()
				.getAllEntries()
				.stream()
				.filter(e -> !e.isDeleted()) // Double-check
				.collect(Collectors.toSet());

		Set<TraceStaticMapping> removed = ChangeCollector.subtract(oldEntries, curEntries);
		Set<TraceStaticMapping> added = ChangeCollector.subtract(curEntries, oldEntries);

		processRemovedEntries(cc, removed);
		processAddedEntries(cc, added);
	}

	void removeEntries(ChangeCollector cc) {
		processRemovedEntries(cc, Set.copyOf(outboundByEntry.keySet()));
	}

	private void processRemovedEntries(ChangeCollector cc, Set<TraceStaticMapping> removed) {
		for (TraceStaticMapping entry : removed) {
			processRemovedEntry(cc, entry);
		}
	}

	private void processRemovedEntry(ChangeCollector cc, TraceStaticMapping entry) {
		MappingEntry me = outboundByEntry.remove(entry);
		if (me == null) {
			return;
		}
		outboundByRange.remove(me.getTraceAddressSnapRange());
		outboundByStaticUrl.removeMapping(me.getStaticProgramUrl(), me);
		plugin.checkAndClearProgram(cc, me);
	}

	private void processAddedEntries(ChangeCollector cc, Set<TraceStaticMapping> added) {
		for (TraceStaticMapping entry : added) {
			processAddedEntry(cc, entry);
		}
	}

	private void processAddedEntry(ChangeCollector cc, TraceStaticMapping entry) {
		MappingEntry me = new MappingEntry(entry);
		outboundByEntry.put(entry, me);
		outboundByRange.put(me.getTraceAddressSnapRange(), me);
		outboundByStaticUrl.put(me.getStaticProgramUrl(), me);
		plugin.checkAndFillProgram(cc, me);
	}

	void clearEntriesForProgram(ChangeCollector cc, InfoPerProgram progInfo) {
		for (MappingEntry me : outboundByStaticUrl.get(progInfo.url)) {
			progInfo.clearProgram(cc, me);
		}
	}

	void fillEntriesForProgram(ChangeCollector cc, InfoPerProgram progInfo) {
		for (MappingEntry me : outboundByStaticUrl.get(progInfo.url)) {
			progInfo.fillProgram(cc, me);
		}
	}

	Set<Program> getOpenMappedProgramsAtSnap(long snap) {
		Set<Program> result = new HashSet<>();
		for (Entry<TraceAddressSnapRange, MappingEntry> out : outboundByRange.entrySet()) {
			MappingEntry me = out.getValue();
			if (me.mapping.isDeleted()) {
				Msg.warn(this, "Encountered deleted mapping: " + me.mapping);
				continue;
			}
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

	ProgramLocation getOpenMappedProgramLocation(Address address, Lifespan span) {
		TraceAddressSnapRange tasr = new ImmutableTraceAddressSnapRange(address, span);
		// max is tasr (single address)
		for (MappingEntry me : outboundByRange.headMap(tasr, true).values()) {
			if (me.mapping.isDeleted()) {
				Msg.warn(this, "Encountered deleted mapping: " + me.mapping);
				continue;
			}
			if (!tasr.intersects(me.getTraceAddressSnapRange())) {
				continue;
			}
			if (me.isStaticProgramOpen()) {
				return me.mapTraceAddressToProgramLocation(address);
			}
		}
		return null;
	}

	private void collectOpenMappedViews(Map<Program, Collection<MappedAddressRange>> result,
			AddressRange rng, Lifespan span) {
		TraceAddressSnapRange tasr = new ImmutableTraceAddressSnapRange(rng, span);
		TraceAddressSnapRange max = new ImmutableTraceAddressSnapRange(rng.getMaxAddress(), span);
		for (MappingEntry me : outboundByRange.headMap(max, true).values()) {
			if (me.mapping.isDeleted()) {
				Msg.warn(this, "Encountered deleted mapping: " + me.mapping);
				continue;
			}
			if (me.program == null) {
				continue;
			}
			if (!tasr.intersects(me.getTraceAddressSnapRange())) {
				continue;
			}
			AddressRange srcRng = me.getTraceRange().intersect(rng);
			AddressRange dstRng = me.mapTraceRangeToProgram(rng);
			result.computeIfAbsent(me.program, p -> new TreeSet<>())
					.add(new MappedAddressRange(srcRng, dstRng));
		}
	}

	Map<Program, Collection<MappedAddressRange>> getOpenMappedViews(AddressSetView set,
			Lifespan span) {
		/**
		 * NB. Cannot use the OverlappingObjectIterator here. Because of the snap dimension, objects
		 * may not be disjoint in the address dimension.
		 */
		Map<Program, Collection<MappedAddressRange>> result = new HashMap<>();
		for (AddressRange rng : set) {
			collectOpenMappedViews(result, rng, span);
		}
		return Collections.unmodifiableMap(result);
	}

	private void collectMappedProgramUrlsInView(Set<URL> result, AddressRange rng, Lifespan span) {
		TraceAddressSnapRange tasr = new ImmutableTraceAddressSnapRange(rng, span);
		TraceAddressSnapRange max = new ImmutableTraceAddressSnapRange(rng.getMaxAddress(), span);
		for (MappingEntry me : outboundByRange.headMap(max, true).values()) {
			if (me.mapping.isDeleted()) {
				Msg.warn(this, "Encountered deleted mapping: " + me.mapping);
				continue;
			}
			if (!tasr.intersects(me.getTraceAddressSnapRange())) {
				continue;
			}
			result.add(me.getStaticProgramUrl());
		}
	}

	Set<URL> getMappedProgramUrlsInView(AddressSetView set, Lifespan span) {
		/**
		 * NB. Cannot use the OverlappingObjectIterator here. Because of the snap dimension, objects
		 * may not be disjoint in the address dimension.
		 */
		Set<URL> result = new HashSet<>();
		for (AddressRange rng : set) {
			collectMappedProgramUrlsInView(result, rng, span);
		}
		return Collections.unmodifiableSet(result);
	}
}
