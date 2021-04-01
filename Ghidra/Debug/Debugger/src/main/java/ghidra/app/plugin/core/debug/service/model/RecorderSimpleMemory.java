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
package ghidra.app.plugin.core.debug.service.model;

import java.util.Map.Entry;
import java.util.NavigableMap;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.function.Predicate;

import ghidra.app.plugin.core.debug.mapping.DebuggerMemoryMapper;
import ghidra.app.plugin.core.debug.service.model.interfaces.AbstractRecorderMemory;
import ghidra.dbg.target.*;
import ghidra.program.model.address.*;

public class RecorderSimpleMemory implements AbstractRecorderMemory {

	private static final int BLOCK_SIZE = 4096;
	private static final long BLOCK_MASK = -1L << 12;

	protected final NavigableMap<Address, TargetMemoryRegion> byMin = new TreeMap<>();
	protected TargetMemory memory;

	public RecorderSimpleMemory() {
	}

	@Override
	public void addRegion(TargetMemoryRegion region, TargetMemory memory) {
		synchronized (this) {
			if (this.memory == null) {
				this.memory = memory;
			}
			byMin.put(region.getRange().getMinAddress(), region);
		}
	}

	@Override
	public boolean removeRegion(TargetObject invalid) {
		if (!(invalid instanceof TargetMemoryRegion)) {
			return false;
		}
		synchronized (this) {
			TargetMemoryRegion invRegion = (TargetMemoryRegion) invalid;
			byMin.remove(invRegion.getRange().getMinAddress());
			return true;
		}
	}

	@Override
	public CompletableFuture<byte[]> readMemory(Address address, int length) {
		synchronized (this) {
			if (memory != null) {
				return memory.readMemory(address, length);
			}
			return CompletableFuture.completedFuture(new byte[0]);
		}
	}

	@Override
	public CompletableFuture<Void> writeMemory(Address address, byte[] data) {
		synchronized (this) {
			if (memory != null) {
				return memory.writeMemory(address, data);
			}
			throw new IllegalArgumentException("read starts outside any address space");
		}
	}

	/**
	 * Get accessible memory, as viewed in the trace
	 * 
	 * @param pred an additional predicate applied via "AND" with accessibility
	 * @param memMapper target-to-trace mapping utility
	 * @return the computed set
	 */
	@Override
	public AddressSet getAccessibleMemory(Predicate<TargetMemory> pred,
			DebuggerMemoryMapper memMapper) {
		synchronized (this) {
			// TODO: Might accomplish by using listeners and tracking the accessible set
			AddressSet accessible = new AddressSet();
			if (memMapper != null) {
				for (Entry<Address, TargetMemoryRegion> ent : byMin.entrySet()) {
					accessible.add(memMapper.targetToTrace(ent.getValue().getRange()));
				}
			}
			return accessible;
		}
	}

	@Override
	public AddressRange alignAndLimitToFloor(Address address, int length) {
		Entry<Address, TargetMemoryRegion> floor = findChainedFloor(address);
		if (floor == null) {
			return null;
		}
		return align(address, length).intersect(floor.getValue().getRange());
	}

	protected Entry<Address, TargetMemoryRegion> findChainedFloor(Address address) {
		synchronized (this) {
			return byMin.floorEntry(address);
		}
	}

	protected AddressRange align(Address address, int length) {
		AddressSpace space = address.getAddressSpace();
		long offset = address.getOffset();
		Address start = space.getAddress(offset & BLOCK_MASK);
		Address end = space.getAddress(((offset + length - 1) & BLOCK_MASK) + BLOCK_SIZE - 1);
		return new AddressRangeImpl(start, end);
	}
}
