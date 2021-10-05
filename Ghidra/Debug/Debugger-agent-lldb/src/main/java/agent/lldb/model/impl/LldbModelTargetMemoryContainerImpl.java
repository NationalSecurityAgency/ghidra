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
package agent.lldb.model.impl;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import com.google.common.collect.Range;
import com.google.common.collect.RangeSet;

import SWIG.SBMemoryRegionInfo;
import agent.lldb.manager.cmd.*;
import agent.lldb.manager.impl.LldbManagerImpl;
import agent.lldb.model.iface2.*;
import ghidra.dbg.error.DebuggerMemoryAccessException;
import ghidra.dbg.error.DebuggerModelAccessException;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.program.model.address.Address;
import ghidra.util.datastruct.WeakValueHashMap;

@TargetObjectSchemaInfo(
	name = "Memory",
	elementResync = ResyncMode.ALWAYS,
	elements = {
		@TargetElementType(type = LldbModelTargetMemoryRegionImpl.class)
	},
	attributes = {
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class LldbModelTargetMemoryContainerImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetMemoryContainer {

	protected final LldbModelTargetProcess process;

	protected final Map<String, LldbModelTargetMemoryRegionImpl> memoryRegions =
		new WeakValueHashMap<>();

	public LldbModelTargetMemoryContainerImpl(LldbModelTargetProcess process) {
		super(process.getModel(), process, "Memory", "MemoryContainer");
		this.process = process;
		requestElements(false);
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return getManager().listMemory(process.getProcess()).thenAccept(byName -> {
			List<TargetObject> regions;
			synchronized (this) {
				regions = byName.stream().map(this::getTargetMemory).collect(Collectors.toList());
			}
			setElements(regions, Map.of(), "Refreshed");
		});
	}

	@Override
	public synchronized LldbModelTargetMemoryRegion getTargetMemory(SBMemoryRegionInfo region) {
		TargetObject targetObject = getMapObject(region);
		if (targetObject != null) {
			LldbModelTargetMemoryRegion targetRegion = (LldbModelTargetMemoryRegion) targetObject;
			targetRegion.setModelObject(region);
			return targetRegion;
		}
		return new LldbModelTargetMemoryRegionImpl(this, region);
	}

	private byte[] readAssist(Address address, ByteBuffer buf, long offset, RangeSet<Long> set) {
		if (set == null) {
			return new byte[0];
		}
		Range<Long> range = set.rangeContaining(offset);
		if (range == null) {
			throw new DebuggerMemoryAccessException("Cannot read at " + address);
		}
		listeners.fire.memoryUpdated(getProxy(), address, buf.array());
		return Arrays.copyOf(buf.array(), (int) (range.upperEndpoint() - range.lowerEndpoint()));
	}

	private void writeAssist(Address address, byte[] data) {
		listeners.fire.memoryUpdated(getProxy(), address, data);
	}

	@Override
	public CompletableFuture<byte[]> readMemory(Address address, int length) {
		return model.gateFuture(doReadMemory(address, length));
	}

	protected CompletableFuture<byte[]> doReadMemory(Address address, int length) {
		LldbManagerImpl manager = getManager();
		if (manager.isWaiting()) {
			throw new DebuggerModelAccessException(
				"Cannot process command readMemory while engine is waiting for events");
		}
		ByteBuffer buf = ByteBuffer.allocate(length);
		long offset = address.getOffset();
		if (!manager.isKernelMode() || address.getAddressSpace().getName().equals("ram")) {
			return manager
					.execute(new LldbReadMemoryCommand(manager, process.getProcess(), address, buf,
						buf.remaining()))
					.thenApply(set -> {
						return readAssist(address, buf, offset, set);
					});
		}
		return CompletableFuture.completedFuture(new byte[length]);
	}

	@Override
	public CompletableFuture<Void> writeMemory(Address address, byte[] data) {
		return model.gateFuture(doWriteMemory(address, data));
	}

	protected CompletableFuture<Void> doWriteMemory(Address address, byte[] data) {
		LldbManagerImpl manager = getManager();
		if (manager.isWaiting()) {
			throw new DebuggerModelAccessException(
				"Cannot process command writeMemory while engine is waiting for events");
		}
		ByteBuffer buf = ByteBuffer.wrap(data);
		if (!manager.isKernelMode() || address.getAddressSpace().getName().equals("ram")) {
			return manager
					.execute(new LldbWriteMemoryCommand(manager, process.getProcess(), address, buf,
						buf.remaining()))
					.thenAccept(___ -> {
						writeAssist(address, data);
					});
		}
		return CompletableFuture.completedFuture(null);
	}

}
