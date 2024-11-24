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
import java.util.concurrent.CompletableFuture;

import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingServicePlugin.ChangeCollector;
import ghidra.app.plugin.core.debug.utils.ProgramURLUtils;
import ghidra.app.services.DebuggerStaticMappingService.MappedAddressRange;
import ghidra.framework.model.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.*;
import ghidra.util.Msg;

class InfoPerProgram implements DomainObjectListener {

	static class NavMultiMap<K, V> {
		private final TreeMap<K, Set<V>> map = new TreeMap<>();

		public boolean put(K k, V v) {
			return map.computeIfAbsent(k, __ -> new HashSet<>()).add(v);
		}

		public boolean remove(K k, V v) {
			Set<V> set = map.get(k);
			if (set == null) {
				return false;
			}
			if (!set.remove(v)) {
				return false;
			}
			if (set.isEmpty()) {
				map.remove(k);
			}
			return true;
		}
	}

	private final DebuggerStaticMappingServicePlugin plugin;
	final Program program;
	final NavMultiMap<Address, MappingEntry> inboundByStaticAddress = new NavMultiMap<>();

	final URL url;

	InfoPerProgram(DebuggerStaticMappingServicePlugin plugin, Program program) {
		this.plugin = plugin;
		this.program = program;
		this.url = ProgramURLUtils.getUrlFromProgram(program);

		program.addListener(this);
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (ev.contains(DomainObjectEvent.FILE_CHANGED) || ev.contains(DomainObjectEvent.RENAMED)) {
			if (!urlMatches()) {
				CompletableFuture.runAsync(plugin::programsChanged, plugin.executor);
			}
		}
	}

	boolean urlMatches() {
		return Objects.equals(url, ProgramURLUtils.getUrlFromProgram(program));
	}

	void clearProgram(ChangeCollector cc, MappingEntry me) {
		assert me.program == program;
		inboundByStaticAddress.remove(me.getStaticAddress(), me);
		me.clearProgram(cc, program);
	}

	void fillProgram(ChangeCollector cc, MappingEntry me) {
		assert me.getStaticProgramUrl().equals(ProgramURLUtils.getUrlFromProgram(program));
		me.fillProgram(cc, program);
		inboundByStaticAddress.put(me.getStaticAddress(), me);
	}

	void clearEntries(ChangeCollector cc) {
		if (url == null) {
			return;
		}
		for (InfoPerTrace info : plugin.traceInfoByTrace.values()) {
			info.clearEntriesForProgram(cc, this);
		}
	}

	void fillEntries(ChangeCollector cc) {
		if (url == null) {
			return;
		}
		for (InfoPerTrace info : plugin.traceInfoByTrace.values()) {
			info.fillEntriesForProgram(cc, this);
		}
	}

	Set<TraceLocation> getOpenMappedTraceLocations(Address address) {
		Set<TraceLocation> result = new HashSet<>();
		for (Set<MappingEntry> set : inboundByStaticAddress.map.headMap(address, true).values()) {
			for (MappingEntry me : set) {
				if (me.mapping.isDeleted()) {
					Msg.warn(this, "Encountered deleted mapping: " + me.mapping);
					continue;
				}
				if (!me.isInProgramRange(address)) {
					continue;
				}
				result.add(me.mapProgramAddressToTraceLocation(address));
			}
		}
		return result;
	}

	TraceLocation getOpenMappedTraceLocation(Trace trace, Address address, long snap) {
		// TODO: Map by trace?
		for (Set<MappingEntry> set : inboundByStaticAddress.map.headMap(address, true).values()) {
			for (MappingEntry me : set) {
				if (me.mapping.isDeleted()) {
					Msg.warn(this, "Encountered deleted mapping: " + me.mapping);
					continue;
				}
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
		}
		return null;
	}

	private void collectOpenMappedViews(Map<TraceSpan, Collection<MappedAddressRange>> result,
			AddressRange rng) {
		for (Set<MappingEntry> set : inboundByStaticAddress.map.headMap(rng.getMaxAddress(), true)
				.values()) {
			for (MappingEntry me : set) {
				if (me.mapping.isDeleted()) {
					Msg.warn(this, "Encountered deleted mapping: " + me.mapping);
					continue;
				}
				// NB. No lifespan to consider
				if (!me.isInProgramRange(rng)) {
					continue;
				}
				AddressRange srcRange = me.getStaticRange().intersect(rng);
				AddressRange dstRange = me.mapProgramRangeToTrace(rng);
				result.computeIfAbsent(me.getTraceSpan(), p -> new TreeSet<>())
						.add(new MappedAddressRange(srcRange, dstRange));
			}
		}
	}

	Map<TraceSpan, Collection<MappedAddressRange>> getOpenMappedViews(AddressSetView set) {
		Map<TraceSpan, Collection<MappedAddressRange>> result = new HashMap<>();
		for (AddressRange rng : set) {
			collectOpenMappedViews(result, rng);
		}
		return Collections.unmodifiableMap(result);
	}
}
