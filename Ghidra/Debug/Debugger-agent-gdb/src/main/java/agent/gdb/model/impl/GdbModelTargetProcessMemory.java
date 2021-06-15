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
package agent.gdb.model.impl;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import org.apache.commons.lang3.exception.ExceptionUtils;

import com.google.common.collect.Range;

import agent.gdb.manager.GdbInferior;
import agent.gdb.manager.impl.GdbMemoryMapping;
import agent.gdb.manager.impl.cmd.GdbCommandError;
import agent.gdb.manager.impl.cmd.GdbStateChangeRecord;
import ghidra.async.AsyncFence;
import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.error.DebuggerMemoryAccessException;
import ghidra.dbg.target.TargetMemory;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.program.model.address.*;
import ghidra.util.Msg;
import ghidra.util.datastruct.WeakValueHashMap;

@TargetObjectSchemaInfo(
	name = "Memory",
	attributes = {
		@TargetAttributeType(type = Void.class) },
	canonicalContainer = true)
public class GdbModelTargetProcessMemory
		extends DefaultTargetObject<GdbModelTargetMemoryRegion, GdbModelTargetInferior>
		implements TargetMemory {
	public static final String NAME = "Memory";

	protected final GdbModelImpl impl;
	protected final GdbInferior inferior;

	protected final Map<BigInteger, GdbModelTargetMemoryRegion> regionsByStart =
		new WeakValueHashMap<>();

	public GdbModelTargetProcessMemory(GdbModelTargetInferior inferior) {
		super(inferior.impl, inferior, NAME, "ProcessMemory");
		this.impl = inferior.impl;
		this.inferior = inferior.inferior;
	}

	protected void updateUsingMappings(Map<BigInteger, GdbMemoryMapping> byStart) {
		List<GdbModelTargetMemoryRegion> regions;
		synchronized (this) {
			regions =
				byStart.values().stream().map(this::getTargetRegion).collect(Collectors.toList());
		}
		setElements(regions, "Refreshed");
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		// Can't use refresh getKnownMappings is only populated by listMappings
		if (inferior.getPid() == null) {
			setElements(List.of(), "Refreshed (while no process)");
			return AsyncUtils.NIL;
		}
		return inferior.listMappings().thenAccept(this::updateUsingMappings);
	}

	protected synchronized GdbModelTargetMemoryRegion getTargetRegion(GdbMemoryMapping mapping) {
		GdbModelTargetMemoryRegion region = regionsByStart.get(mapping.getStart());
		if (region != null && region.isSame(mapping)) {
			return region;
		}
		region = new GdbModelTargetMemoryRegion(this, mapping);
		regionsByStart.put(mapping.getStart(), region);
		return region;
	}

	protected CompletableFuture<byte[]> doReadMemory(Address address, long offset, int length) {
		ByteBuffer buf = ByteBuffer.allocate(length);
		AddressRange range;
		try {
			range = new AddressRangeImpl(address, length);
		}
		catch (AddressOverflowException e) {
			throw new IllegalArgumentException("address,length", e);
		}
		return inferior.readMemory(offset, buf).thenApply(set -> {
			Range<Long> r = set.rangeContaining(offset);
			if (r == null) {
				throw new DebuggerMemoryAccessException("Cannot read at " + address);
			}
			byte[] content =
				Arrays.copyOf(buf.array(), (int) (r.upperEndpoint() - r.lowerEndpoint()));
			listeners.fire.memoryUpdated(this, address, content);
			return content;
		}).exceptionally(e -> {
			e = AsyncUtils.unwrapThrowable(e);
			if (e instanceof GdbCommandError) {
				GdbCommandError gce = (GdbCommandError) e;
				e = new DebuggerMemoryAccessException(
					"Cannot read at " + address + ": " + gce.getInfo().getString("msg"));
				listeners.fire.memoryReadError(this, range, (DebuggerMemoryAccessException) e);
			}
			if (e instanceof DebuggerMemoryAccessException) {
				listeners.fire.memoryReadError(this, range, (DebuggerMemoryAccessException) e);
			}
			return ExceptionUtils.rethrow(e);
		});
	}

	@Override
	public CompletableFuture<byte[]> readMemory(Address address, int length) {
		return impl.gateFuture(doReadMemory(address, address.getOffset(), length));
	}

	@Override
	public CompletableFuture<Void> writeMemory(Address address, byte[] data) {
		CompletableFuture<Void> future =
			inferior.writeMemory(address.getOffset(), ByteBuffer.wrap(data));
		return impl.gateFuture(future.thenAccept(__ -> {
			listeners.fire.memoryUpdated(this, address, data);
		}));
	}

	protected void invalidateMemoryCaches() {
		listeners.fire.invalidateCacheRequested(this);
	}

	public void memoryChanged(long offset, int len) {
		Address address = impl.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
		doReadMemory(address, offset, len).exceptionally(ex -> {
			Msg.error(this, "Failed to update memory contents on memory-changed event", ex);
			return null;
		});
	}

	public CompletableFuture<Void> stateChanged(GdbStateChangeRecord sco) {
		return requestElements(false).thenCompose(__ -> {
			AsyncFence fence = new AsyncFence();
			for (GdbModelTargetMemoryRegion modelRegion : regionsByStart.values()) {
				fence.include(modelRegion.stateChanged(sco));
			}
			return fence.ready();
		});
	}
}
