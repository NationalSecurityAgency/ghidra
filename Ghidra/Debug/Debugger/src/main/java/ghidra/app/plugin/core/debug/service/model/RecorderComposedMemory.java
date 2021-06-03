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

import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.function.Predicate;

import ghidra.app.plugin.core.debug.mapping.DebuggerMemoryMapper;
import ghidra.app.plugin.core.debug.service.model.interfaces.AbstractRecorderMemory;
import ghidra.async.AsyncLazyMap;
import ghidra.async.AsyncUtils;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.DebugModelConventions.AllRequiredAccess;
import ghidra.dbg.target.*;
import ghidra.program.model.address.*;
import ghidra.util.Msg;
import ghidra.util.TriConsumer;
import ghidra.util.datastruct.ListenerSet;

public class RecorderComposedMemory implements AbstractRecorderMemory {

	private static final int BLOCK_SIZE = 4096;
	private static final long BLOCK_MASK = -1L << 12;

	protected final RecorderComposedMemory chain;

	protected final NavigableMap<Address, TargetMemoryRegion> byMin = new TreeMap<>();

	protected final Map<TargetMemoryRegion, TargetMemory> byRegion = new HashMap<>();
	protected final AsyncLazyMap<TargetMemory, AllRequiredAccess> accessibilityByMemory =
		new AsyncLazyMap<>(new HashMap<>(), this::fetchMemAccessibility) {
			public AllRequiredAccess remove(TargetMemory key) {
				AllRequiredAccess acc = super.remove(key);
				if (acc != null) {
					acc.removeChangeListener(getMemAccListeners().fire);
				}
				return acc;
			}
		};

	protected CompletableFuture<AllRequiredAccess> fetchMemAccessibility(TargetMemory mem) {
		return DebugModelConventions.trackAccessibility(mem).thenApply(acc -> {
			acc.addChangeListener(getMemAccListeners().fire);
			return acc;
		});
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
		synchronized (accessibilityByMemory) {
			// TODO: Might accomplish by using listeners and tracking the accessible set
			AddressSet accessible = new AddressSet();
			for (Entry<TargetMemoryRegion, TargetMemory> ent : byRegion.entrySet()) {
				TargetMemory mem = ent.getValue();
				if (!pred.test(mem)) {
					continue;
				}
				AllRequiredAccess acc = accessibilityByMemory.getCompletedMap().get(mem);
				if (acc == null || !acc.getAllAccessibility()) {
					continue;
				}
				accessible.add(memMapper.targetToTrace(ent.getKey().getRange()));
			}
			return accessible;
		}
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	private final ListenerSet<TriConsumer<Boolean, Boolean, Void>> memAccListeners =
		new ListenerSet(TriConsumer.class);

	public RecorderComposedMemory(AbstractRecorderMemory memory) {
		this.chain = (RecorderComposedMemory) memory;
	}

	protected TargetMemory getMemory(Address address, int length) {
		Entry<Address, TargetMemoryRegion> floor = findChainedFloor(address);
		if (floor == null) {
			throw new IllegalArgumentException(
				"address " + address + " is not in any known region");
		}
		Address max;
		try {
			max = address.addNoWrap(length - 1);
		}
		catch (AddressOverflowException e) {
			throw new IllegalArgumentException("read extends beyond the address space");
		}
		if (!floor.getValue().getRange().contains(max)) {
			throw new IllegalArgumentException("read extends beyond a single region");
		}
		return byRegion.get(floor.getValue());
	}

	@Override
	public void addRegion(TargetMemoryRegion region, TargetMemory memory) {
		synchronized (accessibilityByMemory) {
			TargetMemory old = byRegion.put(region, memory);
			assert old == null;
			byMin.put(region.getRange().getMinAddress(), region);
			accessibilityByMemory.get(memory).exceptionally(e -> {
				e = AsyncUtils.unwrapThrowable(e);
				Msg.error(this, "Could not track memory accessibility: " + e.getMessage());
				return null;
			});
		}
	}

	@Override
	public boolean removeRegion(TargetObject invalid) {
		if (!(invalid instanceof TargetMemoryRegion)) {
			return false;
		}
		synchronized (accessibilityByMemory) {
			TargetMemoryRegion invRegion = (TargetMemoryRegion) invalid;
			TargetMemory old = byRegion.remove(invRegion);
			assert old != null;
			byMin.remove(invRegion.getRange().getMinAddress());
			if (!old.isValid() || !byRegion.containsValue(old)) {
				accessibilityByMemory.remove(old);
			}
			return true;
		}
	}

	/*
	protected AllRequiredAccess findChainedMemoryAccess(TargetMemoryRegion region) {
		synchronized (accessibilityByMemory) {
			TargetMemory mem = byRegion.get(region);
			if (mem != null) {
				return accessibilityByMemory.getCompletedMap().get(mem);
			}
			return chain == null ? null : chain.findChainedMemoryAccess(region);
		}
	}
	*/

	public Entry<Address, TargetMemoryRegion> findChainedFloor(Address address) {
		synchronized (accessibilityByMemory) {
			Entry<Address, TargetMemoryRegion> myFloor = byMin.floorEntry(address);
			Entry<Address, TargetMemoryRegion> byChain =
				chain == null ? null : chain.findChainedFloor(address);
			if (byChain == null) {
				return myFloor;
			}
			if (myFloor == null) {
				return byChain;
			}
			int c = myFloor.getKey().compareTo(byChain.getKey());
			if (c < 0) {
				return byChain;
			}
			return myFloor;
		}
	}

	protected AddressRange align(Address address, int length) {
		AddressSpace space = address.getAddressSpace();
		long offset = address.getOffset();
		Address start = space.getAddress(offset & BLOCK_MASK);
		Address end = space.getAddress(((offset + length - 1) & BLOCK_MASK) + BLOCK_SIZE - 1);
		return new AddressRangeImpl(start, end);
	}

	protected AddressRange alignWithLimit(Address address, int length,
			TargetMemoryRegion limit) {
		return align(address, length).intersect(limit.getRange());
	}

	@Override
	public AddressRange alignAndLimitToFloor(Address address, int length) {
		Entry<Address, TargetMemoryRegion> floor = findChainedFloor(address);
		if (floor == null) {
			return null;
		}
		return alignWithLimit(address, length, floor.getValue());
	}

	public AddressRange alignWithOptionalLimit(Address address, int length,
			TargetMemoryRegion limit) {
		if (limit == null) {
			return alignAndLimitToFloor(address, length);
		}
		return alignWithLimit(address, length, limit);
	}

	@Override
	public CompletableFuture<byte[]> readMemory(Address address, int length) {
		synchronized (accessibilityByMemory) {
			TargetMemory mem = getMemory(address, length);
			if (mem != null) {
				return mem.readMemory(address, length);
			}
			return CompletableFuture.completedFuture(new byte[0]);
		}
	}

	@Override
	public CompletableFuture<Void> writeMemory(Address address, byte[] data) {
		synchronized (accessibilityByMemory) {
			TargetMemory mem = getMemory(address, data.length);
			if (mem != null) {
				return mem.writeMemory(address, data);
			}
			throw new IllegalArgumentException("read starts outside any address space");
		}
	}

	public ListenerSet<TriConsumer<Boolean, Boolean, Void>> getMemAccListeners() {
		return memAccListeners;
	}

}
