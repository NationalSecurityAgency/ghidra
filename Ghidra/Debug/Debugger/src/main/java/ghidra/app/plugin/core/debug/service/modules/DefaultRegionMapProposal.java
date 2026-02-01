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

import java.util.*;
import java.util.stream.Collectors;

import ghidra.debug.api.modules.RegionMapProposal;
import ghidra.debug.api.modules.RegionMapProposal.RegionMapEntry;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemoryRegion;

public class DefaultRegionMapProposal
		extends AbstractMapProposal<TraceMemoryRegion, MemoryBlock, RegionMapEntry>
		implements RegionMapProposal {

	public static class DefaultRegionMapEntry
			extends AbstractMapEntry<TraceMemoryRegion, MemoryBlock>
			implements RegionMapEntry {

		public DefaultRegionMapEntry(TraceMemoryRegion region, long snap,
				Program program, MemoryBlock block) {
			super(region.getTrace(), region, snap, program, block);
		}

		@Override
		public TraceMemoryRegion getRegion() {
			return getFromObject();
		}

		@Override
		public String getRegionName() {
			return getRegion().getName(snap);
		}

		@Override
		public Address getRegionMinAddress() {
			return getRegion().getMinAddress(snap);
		}

		@Override
		public AddressRange getFromRange() {
			return getRegion().getRange(snap);
		}

		@Override
		public MemoryBlock getBlock() {
			return getToObject();
		}

		@Override
		public AddressRange getToRange() {
			return new AddressRangeImpl(getBlock().getStart(), getBlock().getEnd());
		}

		@Override
		public void setBlock(Program program, MemoryBlock block) {
			setToObject(program, block);
		}
	}

	protected class RegionMatcher extends Matcher<TraceMemoryRegion, MemoryBlock> {
		public RegionMatcher(TraceMemoryRegion region, long snap, MemoryBlock block) {
			super(region, snap, block);
		}

		@Override
		protected AddressRange getFromRange() {
			return fromObject == null ? null : fromObject.getRange(snap);
		}

		@Override
		protected AddressRange getToRange() {
			return toObject == null ? null
					: new AddressRangeImpl(toObject.getStart(), toObject.getEnd());
		}

		@Override
		protected double computeScore() {
			return computeLengthScore() + computeOffsetScore();
		}

		protected int computeOffsetScore() {
			try {
				long fOff = fromRange.getMinAddress().subtract(fromBase);
				long tOff = toRange.getMinAddress().subtract(toBase);
				if (fOff == tOff) {
					return 10;
				}
			}
			catch (IllegalArgumentException e) {
				// fell-through
			}
			return 0;
		}
	}

	protected class RegionMatcherMap
			extends MatcherMap<Void, TraceMemoryRegion, MemoryBlock, RegionMatcher> {

		public RegionMatcherMap(long snap) {
			super(snap);
		}

		@Override
		protected RegionMatcher newMatcher(TraceMemoryRegion region, MemoryBlock block) {
			return new RegionMatcher(region, snap, block);
		}

		@Override
		protected Void getFromJoinKey(TraceMemoryRegion region) {
			return null;
		}

		@Override
		protected Void getToJoinKey(MemoryBlock block) {
			return null;
		}
	}

	protected static Trace getTrace(Collection<? extends TraceMemoryRegion> regions) {
		if (regions == null || regions.isEmpty()) {
			return null;
		}
		return regions.iterator().next().getTrace();
	}

	protected final List<TraceMemoryRegion> regions;
	protected final long snap;

	protected final Address fromBase;
	protected final Address toBase;
	protected final RegionMatcherMap matchers;

	protected DefaultRegionMapProposal(Collection<? extends TraceMemoryRegion> regions, long snap,
			Program program) {
		super(getTrace(regions), program);
		this.snap = snap;
		this.regions = Collections.unmodifiableList(regions.stream()
				.sorted(Comparator.comparing(r -> r.getMinAddress(snap)))
				.collect(Collectors.toList()));

		this.fromBase = computeFromBase();
		this.toBase = program.getImageBase();
		this.matchers = new RegionMatcherMap(snap);
		processRegions();
		processProgram();
	}

	protected DefaultRegionMapProposal(TraceMemoryRegion region, long snap, Program program,
			MemoryBlock block) {
		super(region.getTrace(), program);
		this.regions = List.of(region);
		this.snap = snap;

		this.fromBase = region.getMinAddress(snap);
		this.toBase = program.getImageBase();
		this.matchers = new RegionMatcherMap(snap);
		processRegions();
		matchers.processToObject(block);
	}

	protected Address computeFromBase() {
		if (regions.isEmpty()) {
			return null;
		}
		return regions.get(0).getMinAddress(snap);
	}

	private void processRegions() {
		for (TraceMemoryRegion region : regions) {
			matchers.processFromObject(region);
		}
	}

	private void processProgram() {
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			matchers.processToObject(block);
		}
	}

	@Override
	public double computeScore() {
		return matchers.averageScore();
	}

	@Override
	public Map<TraceMemoryRegion, RegionMapEntry> computeMap() {
		return matchers.computeMap(
			m -> new DefaultRegionMapEntry(m.fromObject, snap, program, m.toObject));
	}

	@Override
	public MemoryBlock getToObject(TraceMemoryRegion from) {
		return matchers.getToObject(from);
	}
}
