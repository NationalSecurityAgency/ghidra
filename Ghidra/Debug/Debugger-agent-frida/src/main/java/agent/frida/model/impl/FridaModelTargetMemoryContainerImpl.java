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
package agent.frida.model.impl;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import agent.frida.frida.FridaRegionInfo;
import agent.frida.manager.*;
import agent.frida.manager.cmd.FridaReadMemoryCommand;
import agent.frida.manager.cmd.FridaWriteMemoryCommand;
import agent.frida.manager.impl.FridaManagerImpl;
import agent.frida.model.iface2.*;
import agent.frida.model.methods.*;
import ghidra.dbg.DebuggerObjectModel.RefreshBehavior;
import ghidra.dbg.error.DebuggerMemoryAccessException;
import ghidra.dbg.error.DebuggerModelAccessException;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.program.model.address.*;
import ghidra.util.Msg;
import ghidra.util.datastruct.WeakValueHashMap;

@TargetObjectSchemaInfo(
	name = "Memory",
	elementResync = ResyncMode.ALWAYS,
	elements = {
		@TargetElementType(type = FridaModelTargetMemoryRegionImpl.class)
	},
	attributes = {
		@TargetAttributeType(type = Object.class)
	},
	canonicalContainer = true)
public class FridaModelTargetMemoryContainerImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetMemoryContainer {

	protected final FridaModelTargetProcess process;
	protected final FridaModelTargetMemoryScanImpl scan;
	protected final FridaModelTargetMemoryPatchImpl patch;
	protected final FridaModelTargetMemoryProtectImpl prot;
	protected final FridaModelTargetMemoryWatchImpl watch;
	protected final FridaModelTargetUnloadScriptImpl unload;

	protected final Map<String, FridaModelTargetMemoryRegionImpl> memoryRegions =
		new WeakValueHashMap<>();

	public FridaModelTargetMemoryContainerImpl(FridaModelTargetProcess process) {
		super(process.getModel(), process, "Memory", "MemoryContainer");
		this.process = process;

		this.scan = new FridaModelTargetMemoryScanImpl(this, false);
		this.patch = new FridaModelTargetMemoryPatchImpl(this);
		this.prot = new FridaModelTargetMemoryProtectImpl(this, false);
		this.watch = new FridaModelTargetMemoryWatchImpl(this);
		this.unload = new FridaModelTargetUnloadScriptImpl(this, watch.getName());
		this.changeAttributes(List.of(), List.of(), Map.of( //
			scan.getName(), scan, //
			patch.getName(), patch, //
			prot.getName(), prot, //
			watch.getName(), watch, //
			unload.getName(), unload //
		), "Initialized");

		getManager().addEventsListener(this);
		requestElements(RefreshBehavior.REFRESH_ALWAYS);
	}

	public FridaModelTargetMemoryContainerImpl(FridaModelTargetProcess process, String name) {
		super(process.getModel(), process, name, "MemoryContainer");
		this.process = process;

		this.scan = new FridaModelTargetMemoryScanImpl(this, false);
		this.patch = new FridaModelTargetMemoryPatchImpl(this);
		this.prot = new FridaModelTargetMemoryProtectImpl(this, false);
		this.watch = new FridaModelTargetMemoryWatchImpl(this);
		this.unload = new FridaModelTargetUnloadScriptImpl(this, watch.getName());
		this.changeAttributes(List.of(), List.of(), Map.of( //
			scan.getName(), scan, //
			patch.getName(), patch, //
			prot.getName(), prot, //
			watch.getName(), watch, //
			unload.getName(), unload //
		), "Initialized");

		requestElements(RefreshBehavior.REFRESH_NEVER);
	}

	@Override
	public CompletableFuture<Void> requestElements(RefreshBehavior refresh) {
		if (refresh.equals(RefreshBehavior.REFRESH_ALWAYS)) {
			broadcast().invalidateCacheRequested(this);
		}
		return getManager().listMemory(process.getProcess());
	}

	@Override
	public synchronized FridaModelTargetMemoryRegion getTargetMemory(FridaMemoryRegionInfo region) {
		TargetObject targetObject = getMapObject(region);
		if (targetObject != null) {
			FridaModelTargetMemoryRegion targetRegion = (FridaModelTargetMemoryRegion) targetObject;
			targetRegion.setModelObject(region);
			return targetRegion;
		}
		return new FridaModelTargetMemoryRegionImpl(this, region);
	}

	private byte[] readAssist(Address address, ByteBuffer buf, AddressSetView set) {
		if (set == null) {
			return new byte[0];
		}
		AddressRange range = set.getRangeContaining(address);
		if (range == null) {
			throw new DebuggerMemoryAccessException("Cannot read at " + address);
		}
		broadcast().memoryUpdated(getProxy(), address, buf.array());
		return Arrays.copyOf(buf.array(), (int) range.getLength());
	}

	private void writeAssist(Address address, byte[] data) {
		broadcast().memoryUpdated(getProxy(), address, data);
	}

	@Override
	public CompletableFuture<byte[]> readMemory(Address address, int length) {
		return model.gateFuture(doReadMemory(address, length));
	}

	protected CompletableFuture<byte[]> doReadMemory(Address address, int length) {
		FridaManagerImpl manager = getManager();
		if (manager.isWaiting()) {
			throw new DebuggerModelAccessException(
				"Cannot process command readMemory while engine is waiting for events");
		}
		ByteBuffer buf = ByteBuffer.allocate(length);
		if (!manager.isKernelMode() || address.getAddressSpace().getName().equals("ram")) {
			return manager
					.execute(new FridaReadMemoryCommand(manager, address, buf, buf.remaining()))
					.thenApply(set -> {
						return readAssist(address, buf, set);
					});
		}
		return CompletableFuture.completedFuture(new byte[length]);
	}

	@Override
	public CompletableFuture<Void> writeMemory(Address address, byte[] data) {
		return model.gateFuture(doWriteMemory(address, data));
	}

	protected CompletableFuture<Void> doWriteMemory(Address address, byte[] data) {
		FridaManagerImpl manager = getManager();
		if (manager.isWaiting()) {
			throw new DebuggerModelAccessException(
				"Cannot process command writeMemory while engine is waiting for events");
		}
		ByteBuffer buf = ByteBuffer.wrap(data);
		if (!manager.isKernelMode() || address.getAddressSpace().getName().equals("ram")) {
			return manager
					.execute(new FridaWriteMemoryCommand(manager, address, buf, buf.remaining()))
					.thenAccept(___ -> {
						writeAssist(address, data);
					});
		}
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public void regionAdded(FridaProcess proc, FridaRegionInfo info, int index, FridaCause cause) {
		FridaModelTargetMemoryRegion targetRegion;
		FridaMemoryRegionInfo region = info.getRegion(index);
		synchronized (this) {
			/**
			 * It's not a good idea to remove "stale" entries. If the entry's already present, it's
			 * probably because several modules were loaded at once, at it has already had its
			 * sections loaded. Removing it will cause it to load all module sections again!
			 */
			//modulesByName.remove(name);
			targetRegion = getTargetMemory(region);
		}
		if (targetRegion == null) {
			Msg.error(this, "Region " + region.getRangeAddress() + " not found!");
			return;
		}
		changeElements(List.of(), List.of(targetRegion), Map.of(), "Added");
	}

	@Override
	public void regionReplaced(FridaProcess proc, FridaRegionInfo info, int index,
			FridaCause cause) {
		FridaMemoryRegionInfo region = info.getRegion(index);
		changeElements(List.of(), List.of(getTargetMemory(region)), Map.of(), "Replaced");
		FridaModelTargetMemoryRegion targetRegion = getTargetMemory(region);
		changeElements(List.of(), List.of(targetRegion), Map.of(), "Replaced");
	}

	@Override
	public void regionRemoved(FridaProcess proc, FridaRegionInfo info, int index,
			FridaCause cause) {
		FridaModelTargetMemoryRegion targetRegion = getTargetMemory(info.getRegion(index));
		if (targetRegion != null) {
			FridaModelImpl impl = (FridaModelImpl) model;
			impl.deleteModelObject(targetRegion.getModelObject());
		}
		changeElements(List.of(targetRegion.getName()), List.of(), Map.of(), "Removed");
	}
}
