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
package agent.dbgeng.model.impl;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import com.google.common.collect.Range;
import com.google.common.collect.RangeSet;

import agent.dbgeng.manager.DbgModuleMemory;
import agent.dbgeng.manager.cmd.*;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.model.iface2.*;
import ghidra.async.AsyncUtils;
import ghidra.dbg.error.DebuggerMemoryAccessException;
import ghidra.dbg.error.DebuggerModelAccessException;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.program.model.address.Address;
import ghidra.util.datastruct.WeakValueHashMap;

@TargetObjectSchemaInfo(
	name = "Memory",
	elements = {
		@TargetElementType(type = DbgModelTargetMemoryRegionImpl.class) },
	attributes = {
		@TargetAttributeType(type = Void.class) },
	canonicalContainer = true)
public class DbgModelTargetMemoryContainerImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetMemoryContainer {

	protected final DbgModelTargetProcess process;

	protected final Map<String, DbgModelTargetMemoryRegionImpl> memoryRegions =
		new WeakValueHashMap<>();

	public DbgModelTargetMemoryContainerImpl(DbgModelTargetProcess process) {
		super(process.getModel(), process, "Memory", "MemoryContainer");
		this.process = process;
		requestElements(true);
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		DbgModelTargetProcess targetProcess = getParentProcess();
		if (!refresh || !targetProcess.getProcess().equals(getManager().getCurrentProcess())) {
			return AsyncUtils.NIL;
		}
		return listMemory().thenAccept(byName -> {
			List<TargetObject> sections;
			synchronized (this) {
				sections = byName.stream().map(this::getTargetMemory).collect(Collectors.toList());
			}
			setElements(sections, Map.of(), "Refreshed");
		});
	}

	@Override
	public synchronized DbgModelTargetMemoryRegion getTargetMemory(DbgModuleMemory section) {
		DbgModelTargetMemoryRegionImpl region = memoryRegions.get(section.getName());
		if (region != null && region.isSame(section)) {
			return region;
		}
		region = new DbgModelTargetMemoryRegionImpl(this, section);
		memoryRegions.put(section.getName(), region);
		return region;
		// NB: The following logic will cause errors in setElements because of key re-use
		//return memoryRegions.computeIfAbsent(section.getName(),
		//	n -> new DbgModelTargetMemoryRegionImpl(this, section));
	}

	public CompletableFuture<List<DbgModuleMemory>> listMemory() {
		DbgManagerImpl manager = getManager();
		if (manager.isKernelMode()) {
			return manager.execute(new DbgListKernelMemoryRegionsCommand(manager));
		}
		return manager.execute(new DbgListMemoryRegionsCommand(manager));
	}

	public CompletableFuture<byte[]> readVirtualMemory(Address address, int length) {
		DbgManagerImpl manager = getManager();
		if (manager.isWaiting()) {
			throw new DebuggerModelAccessException(
				"Cannot process command readMemory while engine is waiting for events");
		}
		ByteBuffer buf = ByteBuffer.allocate(length);
		long offset = address.getOffset();
		return process.getProcess().readMemory(offset, buf).thenApply(set -> {
			return readAssist(address, buf, offset, set);
		});
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

	public CompletableFuture<Void> writeVirtualMemory(Address address, byte[] data) {
		DbgManagerImpl manager = getManager();
		if (manager.isWaiting()) {
			throw new DebuggerModelAccessException(
				"Cannot process command writeMemory while engine is waiting for events");
		}
		long offset = address.getOffset();
		return process.getProcess().writeMemory(offset, ByteBuffer.wrap(data)).thenAccept(___ -> {
			writeAssist(address, data);
		});
	}

	private void writeAssist(Address address, byte[] data) {
		listeners.fire.memoryUpdated(getProxy(), address, data);
	}

	@Override
	public CompletableFuture<byte[]> readMemory(Address address, int length) {
		return model.gateFuture(doReadMemory(address, length));
	}

	protected CompletableFuture<byte[]> doReadMemory(Address address, int length) {
		DbgManagerImpl manager = getManager();
		if (manager.isWaiting()) {
			throw new DebuggerModelAccessException(
				"Cannot process command readMemory while engine is waiting for events");
		}
		ByteBuffer buf = ByteBuffer.allocate(length);
		long offset = address.getOffset();
		if (!manager.isKernelMode() || address.getAddressSpace().getName().equals("ram")) {
			return manager.execute(new DbgReadMemoryCommand(manager, offset, buf, buf.remaining()))
					.thenApply(set -> {
						return readAssist(address, buf, offset, set);
					});
		}
		if (address.getAddressSpace().getName().equals("phys")) {
			return manager
					.execute(
						new DbgReadPhysicalMemoryCommand(manager, offset, buf, buf.remaining()))
					.thenApply(set -> {
						return readAssist(address, buf, offset, set);
					});
		}
		if (address.getAddressSpace().getName().equals("ctrl")) {
			int processor = 0;
			return manager
					.execute(
						new DbgReadControlCommand(manager, offset, buf, buf.remaining(), processor))
					.thenApply(set -> {
						return readAssist(address, buf, offset, set);
					});
		}
		if (address.getAddressSpace().getName().equals("bus")) {
			int busDataType = 0;
			int busNumber = 0;
			int slotNumber = 0;
			return manager
					.execute(new DbgReadBusDataCommand(manager, offset, buf, buf.remaining(),
						busDataType, busNumber, slotNumber))
					.thenApply(set -> {
						return readAssist(address, buf, offset, set);
					});
		}
		if (address.getAddressSpace().getName().equals("io")) {
			int interfaceType = 0;
			int busNumber = 0;
			int addresSpace = 0;
			return manager
					.execute(new DbgReadIoCommand(manager, offset, buf, buf.remaining(),
						interfaceType, busNumber, addresSpace))
					.thenApply(set -> {
						return readAssist(address, buf, offset, set);
					});
		}
		if (address.getAddressSpace().getName().equals("debug")) {
			return manager
					.execute(new DbgReadDebuggerDataCommand(manager, offset, buf, buf.remaining()))
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
		DbgManagerImpl manager = getManager();
		if (manager.isWaiting()) {
			throw new DebuggerModelAccessException(
				"Cannot process command writeMemory while engine is waiting for events");
		}
		ByteBuffer buf = ByteBuffer.wrap(data);
		long offset = address.getOffset();
		if (!manager.isKernelMode() || address.getAddressSpace().getName().equals("ram")) {
			return manager.execute(new DbgWriteMemoryCommand(manager, offset, buf, buf.remaining()))
					.thenAccept(___ -> {
						writeAssist(address, data);
					});
		}
		if (address.getAddressSpace().getName().equals("phys")) {
			return manager
					.execute(
						new DbgWritePhysicalMemoryCommand(manager, offset, buf, buf.remaining()))
					.thenAccept(___ -> {
						writeAssist(address, data);
					});
		}
		if (address.getAddressSpace().getName().equals("ctrl")) {
			int processor = 0;
			return manager
					.execute(new DbgWriteControlCommand(manager, offset, buf, buf.remaining(),
						processor))
					.thenAccept(___ -> {
						writeAssist(address, data);
					});
		}
		if (address.getAddressSpace().getName().equals("bus")) {
			int busDataType = 0;
			int busNumber = 0;
			int slotNumber = 0;
			return manager
					.execute(new DbgWriteBusDataCommand(manager, offset, buf, buf.remaining(),
						busDataType, busNumber, slotNumber))
					.thenAccept(___ -> {
						writeAssist(address, data);
					});
		}
		if (address.getAddressSpace().getName().equals("io")) {
			int interfaceType = 0;
			int busNumber = 0;
			int addresSpace = 0;
			return manager
					.execute(new DbgWriteIoCommand(manager, offset, buf, buf.remaining(),
						interfaceType, busNumber, addresSpace))
					.thenAccept(___ -> {
						writeAssist(address, data);
					});
		}
		return CompletableFuture.completedFuture(null);
	}

}
