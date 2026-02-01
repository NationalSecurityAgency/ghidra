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
package ghidra.trace.database.program;

import java.util.*;
import java.util.Map.Entry;
import java.util.function.Consumer;

import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.util.LockHold;
import ghidra.util.datastruct.WeakValueHashMap;

public class DBTraceProgramViewMemory extends AbstractDBTraceProgramViewMemory {

	// NB. Keep both per-region and force-full (per-space) block sets ready
	private final Map<TraceMemoryRegion, DBTraceProgramViewMemoryRegionBlock> regionBlocks =
		new WeakValueHashMap<>();
	private final Map<AddressSpace, DBTraceProgramViewMemorySpaceBlock> spaceBlocks =
		new WeakValueHashMap<>();

	private NavigableMap<Address, RegionEntry> regionsByAddress;
	private Map<String, RegionEntry> regionsByName;
	private volatile boolean regionsValid;

	public DBTraceProgramViewMemory(DBTraceProgramView program) {
		super(program);
	}

	protected void forPhysicalSpaces(Consumer<AddressSpace> consumer) {
		for (AddressSpace space : program.getAddressFactory().getAddressSpaces()) {
			// NB. Overlay's isMemory depends on its base space
			// TODO: Allow other?
			// For some reason "other" is omitted from factory.getAddressSet
			if (space.isMemorySpace() && space.getType() != AddressSpace.TYPE_OTHER) {
				consumer.accept(space);
			}
		}
	}

	static class RegionEntry {
		final TraceMemoryRegion region;
		final AddressRange range;

		long snap;

		public RegionEntry(TraceMemoryRegion region, long snap) {
			this.region = region;
			this.range = region.getRange(snap);

			this.snap = snap;
		}

		public boolean isSameAtDifferentSnap(RegionEntry that) {
			if (that == null) {
				return false;
			}
			// Yes, region by identity
			return this.region == that.region && this.range.equals(that.range);
		}
	}

	class RegionsByAddressComputer {
		TreeMap<Address, RegionEntry> map = new TreeMap<>();
		Map<TraceMemoryRegion, Address> addressByRegion = new HashMap<>();

		protected void putDeletingOverlaps(RegionEntry newEntry) {
			// Check if removal is necessary.
			Address newKey = newEntry.range.getMinAddress();
			RegionEntry curEntry = map.get(newKey);
			if (newEntry.isSameAtDifferentSnap(curEntry)) {
				curEntry.snap = newEntry.snap;
				return;
			}

			// Remove all overlapping entries
			Entry<Address, RegionEntry> floorEntry = map.floorEntry(newKey);
			final Address min;
			if (floorEntry != null && floorEntry.getValue().range.contains(newKey)) {
				min = floorEntry.getKey();
			}
			else {
				min = newKey;
			}
			map.subMap(min, true, newEntry.range.getMaxAddress(), true).clear();

			// Remove old entry for the same region, if present
			Address oldKey = addressByRegion.remove(newEntry.region);
			if (oldKey != null) {
				map.remove(oldKey);
			}

			// Put new entry
			map.put(newKey, newEntry);
			addressByRegion.put(newEntry.region, newKey);
		}

		public NavigableMap<Address, RegionEntry> compute() {
			/**
			 * We're banking on the viewport being relatively shallow, and for this to be invoked
			 * relatively infrequently. We build the view from oldest to newest, clobbering old
			 * overlaps as we add the new. Additionally, if a region moves, we must not show its old
			 * position. (NOTE: Philosophically, a region cannot "move", but it's key could be
			 * reused, depending on the connector.)
			 */
			for (long snap : program.viewport.getReversedSnaps()) {
				for (AddressSpace space : getTrace().getBaseAddressFactory().getPhysicalSpaces()) {
					AddressRange range =
						new AddressRangeImpl(space.getMinAddress(), space.getMaxAddress());
					for (TraceMemoryRegion region : memoryManager
							.getRegionsIntersecting(Lifespan.at(snap), range)) {
						RegionEntry entry = new RegionEntry(region, snap);
						putDeletingOverlaps(entry);
					}
				}
			}
			return map;
		}
	}

	protected NavigableMap<Address, RegionEntry> computeRegionsByAddress() {
		return new RegionsByAddressComputer().compute();
	}

	protected Map<String, RegionEntry> computeRegionsByName(Collection<RegionEntry> regions) {
		Map<String, RegionEntry> result = new HashMap<>();
		for (RegionEntry entry : regions) {
			result.put(entry.region.getName(entry.snap), entry);
		}
		return result;
	}

	protected NavigableMap<Address, RegionEntry> getRegionsByAddress() {
		if (!regionsValid) {
			NavigableMap<Address, RegionEntry> byAddr = computeRegionsByAddress();
			regionsByAddress = byAddr;
			regionsByName = computeRegionsByName(byAddr.values());
			regionsValid = true;
		}
		return regionsByAddress;
	}

	protected Map<String, RegionEntry> getRegionsByName() {
		if (!regionsValid) {
			NavigableMap<Address, RegionEntry> byAddr = computeRegionsByAddress();
			regionsByAddress = byAddr;
			regionsByName = computeRegionsByName(byAddr.values());
			regionsValid = true;
		}
		return regionsByName;
	}

	protected void forVisibleRegions(Consumer<RegionEntry> action) {
		for (RegionEntry entry : getRegionsByAddress().values()) {
			action.accept(entry);
		}
	}

	@Override
	void setSnap(long snap) {
		super.setSnap(snap);
		updateBytesChanged(null);
		invalidateRegions();
	}

	protected AddressSet computeRegionsAddressSet() {
		AddressSet result = new AddressSet();
		try (LockHold hold = program.trace.lockRead()) {
			forVisibleRegions(e -> result.add(e.range));
		}
		return result;
	}

	protected AddressSet computeSpacesAddressSet() {
		AddressSet result = new AddressSet();
		try (LockHold hold = program.trace.lockRead()) {
			forPhysicalSpaces(space -> result.add(space.getMinAddress(), space.getMaxAddress()));
		}
		return result;
	}

	@Override
	protected AddressSetView computeAddressSet() {
		return isForceFullView()
				? computeSpacesAddressSet()
				: computeRegionsAddressSet();
	}

	protected MemoryBlock getRegionBlock(RegionEntry entry) {
		return regionBlocks.computeIfAbsent(entry.region,
			r -> new DBTraceProgramViewMemoryRegionBlock(program, entry.region, entry.snap));
	}

	protected MemoryBlock getSpaceBlock(AddressSpace space) {
		return spaceBlocks.computeIfAbsent(space,
			s -> new DBTraceProgramViewMemorySpaceBlock(program, space));
	}

	@Override
	public MemoryBlock getBlock(Address addr) {
		if (isForceFullView()) {
			return getSpaceBlock(addr.getAddressSpace());
		}

		Entry<Address, RegionEntry> entry = getRegionsByAddress().floorEntry(addr);
		if (entry == null || !entry.getValue().range.contains(addr)) {
			return null;
		}
		return getRegionBlock(entry.getValue());
	}

	@Override
	public MemoryBlock getBlock(String blockName) {
		if (isForceFullView()) {
			AddressSpace space = program.getAddressFactory().getAddressSpace(blockName);
			return space == null ? null : getSpaceBlock(space);
		}

		RegionEntry entry = getRegionsByName().get(blockName);
		if (entry == null) {
			return null;
		}
		return getRegionBlock(entry);
	}

	@Override
	public MemoryBlock[] getBlocks() {
		List<MemoryBlock> result = new ArrayList<>();
		if (isForceFullView()) {
			forPhysicalSpaces(space -> result.add(getSpaceBlock(space)));
		}
		else {
			forVisibleRegions(reg -> result.add(getRegionBlock(reg)));
		}
		Collections.sort(result, Comparator.comparing(b -> b.getStart()));
		return result.toArray(new MemoryBlock[result.size()]);
	}

	@Override
	public AddressSetView getExecuteSet() {
		AddressSet result = new AddressSet();
		forVisibleRegions(e -> {
			if (e.region.isExecute(e.snap)) {
				result.add(e.range);
			}
		});
		return result;
	}

	protected void invalidateRegions() {
		regionsValid = false;
		if (regionBlocks != null) { // <init> order
			regionBlocks.clear();
		}
		if (!isForceFullView()) {
			invalidateAddressSet();
		}
	}

	public void updateAddSpaceBlock(AddressSpace space) {
		// Nothing. Cache will construct it upon request, lazily
	}

	public void updateDeleteSpaceBlock(AddressSpace space) {
		spaceBlocks.remove(space);
	}

	public void updateRefreshBlocks() {
		invalidateRegions();
		spaceBlocks.clear();
	}

	public void updateBytesChanged(AddressRange range) {
		if (regionBlocks == null) { // <init> order
			return;
		}
		cache.invalidate(range);
	}
}
