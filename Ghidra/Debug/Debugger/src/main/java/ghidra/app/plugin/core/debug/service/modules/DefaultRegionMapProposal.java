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

import ghidra.app.services.RegionMapProposal;
import ghidra.app.services.RegionMapProposal.RegionMapEntry;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemoryRegion;

public class DefaultRegionMapProposal
		extends AbstractMapProposal<TraceMemoryRegion, MemoryBlock, RegionMapEntry>
		implements RegionMapProposal {

	public static class DefaultRegionMapEntry
			extends AbstractMapEntry<TraceMemoryRegion, MemoryBlock>
			implements RegionMapEntry {

		public DefaultRegionMapEntry(TraceMemoryRegion region,
				Program program, MemoryBlock block) {
			super(region.getTrace(), region, program, block);
		}

		@Override
		public TraceMemoryRegion getRegion() {
			return getFromObject();
		}

		@Override
		public AddressRange getFromRange() {
			return getRegion().getRange();
		}

		@Override
		public Lifespan getFromLifespan() {
			return getRegion().getLifespan();
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
		public RegionMatcher(TraceMemoryRegion region, MemoryBlock block) {
			super(region, block);
		}

		@Override
		protected AddressRange getFromRange() {
			return fromObject == null ? null : fromObject.getRange();
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
			} catch (IllegalArgumentException e) {
				// fell-through
			}
			return 0;
		}
	}

	protected class RegionMatcherMap
			extends MatcherMap<Void, TraceMemoryRegion, MemoryBlock, RegionMatcher> {
		@Override
		protected RegionMatcher newMatcher(TraceMemoryRegion region, MemoryBlock block) {
			return new RegionMatcher(region, block);
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
	protected final Address fromBase;
	protected final Address toBase;
	protected final RegionMatcherMap matchers = new RegionMatcherMap();

	protected DefaultRegionMapProposal(Collection<? extends TraceMemoryRegion> regions,
			Program program) {
		super(getTrace(regions), program);
		this.regions = Collections.unmodifiableList(regions.stream()
				.sorted(Comparator.comparing(r -> r.getMinAddress()))
				.collect(Collectors.toList()));
		this.fromBase = computeFromBase();
		this.toBase = program.getImageBase();
		processRegions();
		processProgram();
	}

	protected DefaultRegionMapProposal(TraceMemoryRegion region, Program program,
			MemoryBlock block) {
		super(region.getTrace(), program);
		this.regions = List.of(region);
		this.fromBase = region.getMinAddress();
		this.toBase = program.getImageBase();
		processRegions();
		matchers.processToObject(block);
	}

	protected Address computeFromBase() {
		if (regions.isEmpty()) {
			return null;
		}
		return regions.get(0).getMinAddress();
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
		return matchers
				.computeMap(m -> new DefaultRegionMapEntry(m.fromObject, program, m.toObject));
	}

	@Override
	public MemoryBlock getToObject(TraceMemoryRegion from) {
		return matchers.getToObject(from);
	}
}
