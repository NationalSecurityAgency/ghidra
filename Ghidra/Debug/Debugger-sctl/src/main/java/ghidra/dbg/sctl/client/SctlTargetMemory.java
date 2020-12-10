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
package ghidra.dbg.sctl.client;

import java.util.List;
import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.memory.*;
import ghidra.dbg.target.TargetMemory;
import ghidra.program.model.address.Address;

public class SctlTargetMemory extends DefaultTargetObject<SctlTargetMemoryRegion, SctlTargetProcess>
		implements TargetMemory<SctlTargetMemory> {

	protected final SctlClient client;

	private final CachedMemory memCache =
		new CachedMemory(this::rawReadMemory, this::rawWriteMemory);
	private final MemoryWriter memWriter = memCache;
	private final MemoryReader memReader = memCache;

	public SctlTargetMemory(SctlTargetProcess process) {
		super(process.client, process, "Memory", "Memory");
		this.client = process.client;
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		if (refresh) {
			parent.lazyStat.forget();
		}
		return parent.lazyStat.request();
	}

	@Override
	public CompletableFuture<byte[]> readMemory(Address address, int length) {
		return memReader.readMemory(client.addrMapper.mapAddressToOffset(address), length);
	}

	private CompletableFuture<byte[]> rawReadMemory(long offset, int length) {
		return client.readMemory(parent.primaryCtlid, offset, length).thenApply(data -> {
			notifyUpdate(offset, data);
			return data;
		});
	}

	@Override
	public CompletableFuture<Void> writeMemory(Address address, byte[] data) {
		return memWriter.writeMemory(client.addrMapper.mapAddressToOffset(address), data);
	}

	private CompletableFuture<Void> rawWriteMemory(long offset, byte[] data) {
		return client.writeMemory(parent.primaryCtlid, offset, data).thenAccept(__ -> {
			notifyUpdate(offset, data);
		});
	}

	protected void notifyUpdate(long offset, byte[] data) {
		Address address = client.addrMapper.mapOffsetToAddress(offset);
		listeners.fire(TargetMemoryListener.class).memoryUpdated(this, address, data);
	}

	@Override
	public CompletableFuture<Void> invalidateCaches() {
		memCache.clear();
		return AsyncUtils.NIL;
	}

	protected void clearRegions() {
		setElements(List.of(), "Refreshing");
	}

	protected void addRegion(SctlTargetMemoryRegion region) {
		// TODO: Rewrite this to use setElements after all regions are collected
		changeElements(List.of(), List.of(region), "Refreshed");
	}

	protected void invalidateMemoryCaches() {
		memCache.clear();
		listeners.fire.invalidateCacheRequested(this);
	}
}
