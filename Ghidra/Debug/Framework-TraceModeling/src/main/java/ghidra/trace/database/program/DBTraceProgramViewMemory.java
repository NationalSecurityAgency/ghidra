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
import java.util.function.Consumer;
import java.util.function.Function;

import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.util.LockHold;
import ghidra.util.datastruct.WeakValueHashMap;

public class DBTraceProgramViewMemory extends AbstractDBTraceProgramViewMemory {
	// I think size should be about how many instructions may appear on screen at once.
	// Double for good measure (in case windows are cloned, maximized, etc.)
	private static final int REGION_CACHE_BY_ADDRESS_SIZE = 300;

	// Size should be about how many distinct regions are involved in displayed instructions
	// Probably only about 5, but cost of 30 is still small.
	private static final int REGION_CACHE_BY_NAME_SIZE = 30;

	// NB. Keep both per-region and force-full (per-space) block sets ready
	private final Map<TraceMemoryRegion, DBTraceProgramViewMemoryRegionBlock> regionBlocks =
		new WeakValueHashMap<>();
	private final Map<AddressSpace, DBTraceProgramViewMemorySpaceBlock> spaceBlocks =
		new WeakValueHashMap<>();
	private final Map<Address, TraceMemoryRegion> regionCacheByAddress = new LinkedHashMap<>() {
		protected boolean removeEldestEntry(Map.Entry<Address, TraceMemoryRegion> eldest) {
			return this.size() > REGION_CACHE_BY_ADDRESS_SIZE;
		}
	};
	private final Map<String, TraceMemoryRegion> regionCacheByName = new LinkedHashMap<>() {
		protected boolean removeEldestEntry(Map.Entry<String, TraceMemoryRegion> eldest) {
			return this.size() > REGION_CACHE_BY_NAME_SIZE;
		}
	};

	public DBTraceProgramViewMemory(DBTraceProgramView program) {
		super(program);
	}

	protected TraceMemoryRegion getTopRegion(Function<Long, TraceMemoryRegion> regFunc) {
		return program.viewport.getTop(s -> {
			// TODO: There is probably an early-bail condition I can check for.
			TraceMemoryRegion reg = regFunc.apply(s);
			if (reg != null && program.isRegionVisible(reg)) {
				return reg;
			}
			return null;
		});
	}

	protected void forVisibleRegions(Consumer<? super TraceMemoryRegion> action) {
		for (long s : program.viewport.getOrderedSnaps()) {
			// NOTE: This is slightly faster than new AddressSet(mm.getRegionsAddressSet(snap))
			for (TraceMemoryRegion reg : memoryManager.getRegionsAtSnap(s)) {
				if (program.isRegionVisible(reg)) {
					action.accept(reg);
				}
			}
		}
	}

	@Override
	void setSnap(long snap) {
		super.setSnap(snap);
		updateBytesChanged(null);
	}

	@Override
	protected void recomputeAddressSet() {
		AddressSet temp = new AddressSet();
		try (LockHold hold = program.trace.lockRead()) {
			// TODO: Performance test this
			forVisibleRegions(reg -> temp.add(reg.getRange()));
		}
		addressSet = temp;
	}

	protected MemoryBlock getRegionBlock(TraceMemoryRegion region) {
		return regionBlocks.computeIfAbsent(region,
			r -> new DBTraceProgramViewMemoryRegionBlock(program, region));
	}

	protected MemoryBlock getSpaceBlock(AddressSpace space) {
		return spaceBlocks.computeIfAbsent(space,
			s -> new DBTraceProgramViewMemorySpaceBlock(program, space));
	}

	@Override
	public MemoryBlock getBlock(Address addr) {
		if (forceFullView) {
			return getSpaceBlock(addr.getAddressSpace());
		}
		TraceMemoryRegion region = regionCacheByAddress.get(addr);
		if (region != null && !region.isDeleted()) {
			/**
			 * TODO: This is assuming: 1) We never fork in non-scratch space. 2) Regions are not
			 * created in scratch space. These are convention, but weren't originally intended to be
			 * rules. This makes them rules.
			 */
			long s = program.viewport.getReversedSnaps().get(0);
			if (region.getLifespan().contains(s)) {
				return getRegionBlock(region);
			}
		}
		region = getTopRegion(s -> memoryManager.getRegionContaining(s, addr));
		if (region != null) {
			regionCacheByAddress.put(addr, region);
			return getRegionBlock(region);
		}
		return null;
	}

	@Override
	public MemoryBlock getBlock(String blockName) {
		if (forceFullView) {
			AddressSpace space = program.getAddressFactory().getAddressSpace(blockName);
			return space == null ? null : getSpaceBlock(space);
		}
		TraceMemoryRegion region = regionCacheByName.get(blockName);
		if (region != null && !region.isDeleted()) {
			long s = program.viewport.getReversedSnaps().get(0);
			if (region.getLifespan().contains(s)) {
				return getRegionBlock(region);
			}
		}
		region = getTopRegion(s -> memoryManager.getLiveRegionByPath(s, blockName));
		if (region != null) {
			regionCacheByName.put(blockName, region);
			return getRegionBlock(region);
		}
		return null;
	}

	@Override
	public MemoryBlock[] getBlocks() {
		List<MemoryBlock> result = new ArrayList<>();
		if (forceFullView) {
			forPhysicalSpaces(space -> result.add(getSpaceBlock(space)));
		}
		else {
			forVisibleRegions(reg -> result.add(getRegionBlock(reg)));
		}
		Collections.sort(result, Comparator.comparing(b -> b.getStart()));
		return result.toArray(new MemoryBlock[result.size()]);
	}

	public void updateAddRegionBlock(TraceMemoryRegion region) {
		// TODO: add block to cache?
		addRange(region.getRange());
	}

	public void updateChangeRegionBlockName(TraceMemoryRegion region) {
		// Nothing. Block name is taken from region, uncached
	}

	public void updateChangeRegionBlockFlags(TraceMemoryRegion region) {
		// Nothing. Block flags are taken from region, uncached
	}

	public void updateChangeRegionBlockRange(TraceMemoryRegion region, AddressRange oldRange,
			AddressRange newRange) {
		changeRange(oldRange, newRange);
	}

	public void updateDeleteRegionBlock(TraceMemoryRegion region) {
		regionBlocks.remove(region);
		removeRange(region.getRange());
	}

	public void updateAddSpaceBlock(AddressSpace space) {
		// Nothing. Cache will construct it upon request, lazily
	}

	public void updateDeleteSpaceBlock(AddressSpace space) {
		spaceBlocks.remove(space);
	}

	public void updateRefreshBlocks() {
		regionBlocks.clear();
		spaceBlocks.clear();
		recomputeAddressSet();
	}

	public void updateBytesChanged(AddressRange range) {
		if (regionBlocks == null) { // <init> order
			return;
		}
		cache.invalidate(range);
	}
}
