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
package ghidra.dbg.gadp.client;

import java.util.concurrent.CompletableFuture;

import com.google.protobuf.ByteString;

import ghidra.dbg.error.DebuggerMemoryAccessException;
import ghidra.dbg.gadp.client.annot.GadpEventHandler;
import ghidra.dbg.gadp.protocol.Gadp;
import ghidra.dbg.memory.MemoryReader;
import ghidra.dbg.memory.MemoryWriter;
import ghidra.dbg.target.TargetMemory;
import ghidra.lifecycle.Internal;
import ghidra.program.model.address.*;

public interface GadpClientTargetMemory extends GadpClientTargetObject, TargetMemory {

	@Internal
	default MemoryReader getRawReader(AddressSpace space) {
		return (addr, length) -> rawReadMemory(space, addr, length);
	}

	@Internal
	default CompletableFuture<byte[]> rawReadMemory(AddressSpace space, long addr, int length) {
		getDelegate().assertValid();
		Address min = space.getAddress(addr);
		AddressRange range;
		try {
			range = new AddressRangeImpl(min, length);
		}
		catch (AddressOverflowException e) {
			throw new IllegalArgumentException("addr=" + addr + ",len=" + length);
		}
		return getModel().sendChecked(Gadp.MemoryReadRequest.newBuilder()
				.setPath(GadpValueUtils.makePath(getPath()))
				.setRange(GadpValueUtils.makeRange(range)),
			Gadp.MemoryReadReply.getDefaultInstance()).thenApply(rep -> {
				return rep.getContent().toByteArray();
			});
	}

	@Override
	default CompletableFuture<byte[]> readMemory(Address address, int length) {
		return getDelegate().getMemoryCache(address.getAddressSpace())
				.readMemory(address.getOffset(), length);
	}

	@Internal
	default MemoryWriter getRawWriter(AddressSpace space) {
		return (addr, data) -> rawWriteMemory(space, addr, data);
	}

	@Internal
	default CompletableFuture<Void> rawWriteMemory(AddressSpace space, long addr, byte[] data) {
		getDelegate().assertValid();
		Address min = space.getAddress(addr);
		return getModel().sendChecked(Gadp.MemoryWriteRequest.newBuilder()
				.setPath(GadpValueUtils.makePath(getPath()))
				.setStart(GadpValueUtils.makeAddress(min))
				.setContent(ByteString.copyFrom(data)),
			Gadp.MemoryWriteReply.getDefaultInstance()).thenApply(rep -> null);
	}

	@Override
	default CompletableFuture<Void> writeMemory(Address address, byte[] data) {
		return getDelegate().getMemoryCache(address.getAddressSpace())
				.writeMemory(address.getOffset(), data);
	}

	@GadpEventHandler(Gadp.EventNotification.EvtCase.MEMORY_UPDATE_EVENT)
	default void handleMemoryUpdateEvent(Gadp.EventNotification notification) {
		Gadp.MemoryUpdateEvent evt = notification.getMemoryUpdateEvent();
		Address address = GadpValueUtils.getAddress(getModel(), evt.getAddress());
		byte[] data = evt.getContent().toByteArray();
		DelegateGadpClientTargetObject delegate = getDelegate();
		delegate.getMemoryCache(address.getAddressSpace()).updateMemory(address.getOffset(), data);
		delegate.getListeners().fire.memoryUpdated(this, address, data);
	}

	@GadpEventHandler(Gadp.EventNotification.EvtCase.MEMORY_ERROR_EVENT)
	default void handleMemoryErrorEvent(Gadp.EventNotification notification) {
		Gadp.MemoryErrorEvent evt = notification.getMemoryErrorEvent();
		AddressRange range = GadpValueUtils.getAddressRange(getModel(), evt.getRange());
		String message = evt.getMessage();
		// Errors are not cached, but recorded in trace
		getDelegate().getListeners().fire.memoryReadError(this, range,
			new DebuggerMemoryAccessException(message));
	}
}
