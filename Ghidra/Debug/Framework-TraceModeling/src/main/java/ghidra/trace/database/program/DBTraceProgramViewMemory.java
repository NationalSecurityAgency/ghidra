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

import com.google.common.cache.CacheBuilder;

import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.trace.database.memory.DBTraceMemoryRegion;

public class DBTraceProgramViewMemory extends AbstractDBTraceProgramViewMemory {

	private final Map<DBTraceMemoryRegion, DBTraceProgramViewMemoryBlock> blocks =
		CacheBuilder.newBuilder().removalListener(this::blockRemoved).weakValues().build().asMap();

	public DBTraceProgramViewMemory(DBTraceProgramView program) {
		super(program);
	}

	protected DBTraceMemoryRegion getTopRegion(Function<Long, DBTraceMemoryRegion> regFunc) {
		return program.viewport.getTop(s -> {
			// TODO: There is probably an early-bail condition I can check for.
			DBTraceMemoryRegion reg = regFunc.apply(s);
			if (reg != null && program.isRegionVisible(reg)) {
				return reg;
			}
			return null;
		});
	}

	protected void forVisibleRegions(Consumer<? super DBTraceMemoryRegion> action) {
		for (long s : program.viewport.getOrderedSnaps()) {
			// NOTE: This is slightly faster than new AddressSet(mm.getRegionsAddressSet(snap))
			for (DBTraceMemoryRegion reg : memoryManager.getRegionsAtSnap(s)) {
				if (program.isRegionVisible(reg)) {
					action.accept(reg);
				}
			}
		}
	}

	@Override
	protected void recomputeAddressSet() {
		AddressSet temp = new AddressSet();
		// TODO: Performance test this
		forVisibleRegions(reg -> temp.add(reg.getRange()));
		addressSet = temp;
	}

	protected MemoryBlock getBlock(DBTraceMemoryRegion region) {
		return blocks.computeIfAbsent(region,
			r -> new DBTraceProgramViewMemoryBlock(program, region));
	}

	@Override
	public MemoryBlock getBlock(Address addr) {
		DBTraceMemoryRegion region = getTopRegion(s -> memoryManager.getRegionContaining(s, addr));
		return region == null ? null : getBlock(region);
	}

	@Override
	public MemoryBlock getBlock(String blockName) {
		DBTraceMemoryRegion region =
			getTopRegion(s -> memoryManager.getLiveRegionByPath(s, blockName));
		return region == null ? null : getBlock(region);
	}

	@Override
	public MemoryBlock[] getBlocks() {
		List<MemoryBlock> result = new ArrayList<>();
		forVisibleRegions(reg -> result.add(getBlock(reg)));
		return result.toArray(new MemoryBlock[result.size()]);
	}

	public void updateAddBlock(DBTraceMemoryRegion region) {
		// TODO: add block to cache?
		addRange(region.getRange());
	}

	public void updateChangeBlockName(DBTraceMemoryRegion region) {
		// Nothing. Block name is taken from region, uncached
	}

	public void updateChangeBlockFlags(DBTraceMemoryRegion region) {
		// Nothing. Block flags are taken from region, uncached
	}

	public void updateChangeBlockRange(DBTraceMemoryRegion region, AddressRange oldRange,
			AddressRange newRange) {
		// TODO: update cached block? Nothing to update.
		changeRange(oldRange, newRange);
	}

	public void updateDeleteBlock(DBTraceMemoryRegion region) {
		blocks.remove(region);
		removeRange(region.getRange());
	}

	public void updateRefreshBlocks() {
		blocks.clear();
		recomputeAddressSet();
	}
}
