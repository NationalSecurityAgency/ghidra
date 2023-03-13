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

import agent.gdb.manager.GdbInferior;
import agent.gdb.manager.impl.GdbMemoryMapping;
import agent.gdb.manager.impl.cmd.GdbCommandError;
import agent.gdb.manager.impl.cmd.GdbStateChangeRecord;
import generic.ULongSpan;
import ghidra.async.AsyncFence;
import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerObjectModel.RefreshBehavior;
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

	protected CompletableFuture<Map<BigInteger, GdbMemoryMapping>> defaultUsingAddressSize() {
		return inferior.evaluate("sizeof(int*)").thenApply(sizeStr -> {
			int size;
			try {
				size = Integer.parseInt(sizeStr);
			}
			catch (NumberFormatException e) {
				throw new GdbCommandError("Couldn't determine address size: " + e);
			}

			BigInteger start = BigInteger.ZERO;
			BigInteger end = BigInteger.ONE.shiftLeft(size * 8);
			if (size >= 0 && size < 8) {
				GdbMemoryMapping mapping = new GdbMemoryMapping(start, end,
					end.subtract(start), BigInteger.ZERO, "rwx", "default");
				return Map.of(start, mapping);
			}
			if (size == 8) {
				// TODO: This split shouldn't be necessary.
				BigInteger lowEnd = BigInteger.valueOf(Long.MAX_VALUE);
				BigInteger highStart = lowEnd.add(BigInteger.ONE);

				GdbMemoryMapping lowMapping = new GdbMemoryMapping(start, lowEnd,
					lowEnd.subtract(start), BigInteger.ZERO, "rwx", "defaultLow");
				GdbMemoryMapping highMapping = new GdbMemoryMapping(highStart, end,
					end.subtract(highStart), BigInteger.ZERO, "rwx", "defaultHigh");
				return Map.of(start, lowMapping, highStart, highMapping);
			}
			throw new GdbCommandError("Unexpected address size: " + size);
		});
	}

	protected void updateUsingMappings(Map<BigInteger, GdbMemoryMapping> byStart) {
		synchronized (this) {
			if (!valid) {
				setElements(List.of(), "Refreshed");
			}
		}
		CompletableFuture<Map<BigInteger, GdbMemoryMapping>> maybeDefault =
			byStart.isEmpty() ? defaultUsingAddressSize()
					: CompletableFuture.completedFuture(byStart);
		maybeDefault.thenAccept(mappings -> {
			List<GdbModelTargetMemoryRegion> regions;
			synchronized (this) {
				regions = mappings.values()
						.stream()
						.map(this::getTargetRegion)
						.collect(Collectors.toList());
			}
			setElements(regions, "Refreshed");
		}).exceptionally(ex -> {
			Msg.info(this, "Failed to update regions: " + ex);
			return null;
		});
	}

	@Override
	protected CompletableFuture<Void> requestElements(RefreshBehavior refresh) {
		// Can't use refresh getKnownMappings is only populated by listMappings
		return doRefresh();
	}

	protected CompletableFuture<Void> doRefresh() {
		if (inferior.getPid() == null) {
			setElements(List.of(), "Refreshed (while no process)");
			return AsyncUtils.NIL;
		}
		return inferior.listMappings().exceptionally(ex -> {
			Msg.error(this, "Could not list regions. Using default.");
			return Map.of(); // empty map will be replaced with default
		}).thenAccept(this::updateUsingMappings);
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
			ULongSpan s = set.spanContaining(offset);
			if (s == null) {
				throw new DebuggerMemoryAccessException("Cannot read at " + address);
			}
			byte[] content = Arrays.copyOf(buf.array(), (int) s.length());
			broadcast().memoryUpdated(this, address, content);
			return content;
		}).exceptionally(e -> {
			e = AsyncUtils.unwrapThrowable(e);
			if (e instanceof GdbCommandError) {
				GdbCommandError gce = (GdbCommandError) e;
				e = new DebuggerMemoryAccessException(
					"Cannot read at " + address + ": " + gce.getInfo().getString("msg"));
				broadcast().memoryReadError(this, range, (DebuggerMemoryAccessException) e);
			}
			if (e instanceof DebuggerMemoryAccessException) {
				broadcast().memoryReadError(this, range, (DebuggerMemoryAccessException) e);
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
			broadcast().memoryUpdated(this, address, data);
		}));
	}

	protected void invalidateMemoryCaches() {
		broadcast().invalidateCacheRequested(this);
	}

	public void memoryChanged(long offset, int len) {
		Address address = impl.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
		doReadMemory(address, offset, len).exceptionally(ex -> {
			Msg.error(this, "Failed to update memory contents on memory-changed event", ex);
			return null;
		});
	}

	// TODO: Seems this is only called when sco.getState() == STOPPED.
	// Maybe should name it such
	public CompletableFuture<Void> stateChanged(GdbStateChangeRecord sco) {
		return doRefresh().thenCompose(__ -> {
			AsyncFence fence = new AsyncFence();
			for (GdbModelTargetMemoryRegion modelRegion : regionsByStart.values()) {
				fence.include(modelRegion.stateChanged(sco));
			}
			return fence.ready();
		});
	}

	protected CompletableFuture<?> refreshInternal() {
		return doRefresh().exceptionally(ex -> {
			impl.reportError(this, "Problem refreshing inferior's memory regions", ex);
			return null;
		});
	}
}
