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
package ghidra.pcode.exec.trace.data;

import ghidra.program.model.address.*;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.property.*;

/**
 * The default trace-property access shim
 *
 * @param <T> the type of the property's values
 */
public class DefaultPcodeTracePropertyAccess<T>
		implements PcodeTracePropertyAccess<T> {

	protected final InternalPcodeTraceDataAccess data;
	protected final String name;
	protected final Class<T> type;

	protected TracePropertyMapOperations<T> po;

	/**
	 * Construct the shim
	 * 
	 * @param data the trace-data access shim providing this property access shim
	 * @param name the name of the property
	 * @param type the type of the property
	 */
	protected DefaultPcodeTracePropertyAccess(InternalPcodeTraceDataAccess data, String name,
			Class<T> type) {
		this.data = data;
		this.name = name;
		this.type = type;

		this.po = data.getPropertyOps(name, type, false);
	}

	/**
	 * Get the interface for accessing the trace property on memory or registers
	 * 
	 * @param createIfAbsent whether to create the missing property (and space in the case of a
	 *            register property)
	 * @return the operations, or null
	 */
	protected TracePropertyMapOperations<T> getPropertyOperations(boolean createIfAbsent) {
		if (po == null) {
			return po = data.getPropertyOps(name, type, createIfAbsent);
		}
		return po;
	}

	/**
	 * Extension point: Alternative logic when the trace property is null
	 * 
	 * @param hostAddress the trace address (in the host platform)
	 * @return the alternative value, or null
	 */
	protected T whenNull(Address hostAddress) {
		return null;
	}

	@Override
	public T get(Address address) {
		Address hostAddr = data.getPlatform().mapGuestToHost(address);
		if (hostAddr == null) {
			return null;
		}
		TracePropertyMapOperations<T> ops = getPropertyOperations(false);
		if (ops == null) {
			return whenNull(hostAddr);
		}
		Address overlayAddr = toOverlay(ops, hostAddr);
		return ops.get(data.getSnap(), overlayAddr);
	}

	@Override
	public void put(Address address, T value) {
		Address hostAddr = data.getPlatform().mapGuestToHost(address);
		if (hostAddr == null) {
			// TODO: Warn?
			return;
		}
		Lifespan span = Lifespan.nowOnMaybeScratch(data.getSnap());
		TracePropertyMapOperations<T> ops = getPropertyOperations(true);
		ops.set(span, toOverlay(ops, hostAddr), value);
	}

	@Override
	public void clear(AddressRange range) {
		AddressRange hostRange = data.getPlatform().mapGuestToHost(range);
		if (hostRange == null) {
			// TODO: Warn?
			return;
		}
		Lifespan span = Lifespan.nowOnMaybeScratch(data.getSnap());
		TracePropertyMapOperations<T> ops = getPropertyOperations(false);
		if (ops == null) {
			return;
		}
		ops.clear(span, toOverlay(ops, hostRange));
	}

	/**
	 * If this provides access to an overlay space, translate the physical address to it
	 * 
	 * @param ops the property operations
	 * @param address the physical address
	 * @return the overlay address, or the same address
	 */
	protected Address toOverlay(TracePropertyMapOperations<T> ops, Address address) {
		if (ops instanceof TracePropertyMap) {
			return address;
		}
		if (ops instanceof TracePropertyMapSpace<T> mapSpace) {
			return mapSpace.getAddressSpace().getOverlayAddress(address);
		}
		throw new AssertionError();
	}

	/**
	 * If this provides access to an overlay space, translate the physical range to it
	 * 
	 * @param ops the property operations
	 * @param range the physical range
	 * @return the overlay range, or the same range
	 */
	protected AddressRange toOverlay(TracePropertyMapOperations<T> ops, AddressRange range) {
		if (ops instanceof TracePropertyMap) {
			return range;
		}
		if (ops instanceof TracePropertyMapSpace<T> mapSpace) {
			AddressSpace space = mapSpace.getAddressSpace();
			return new AddressRangeImpl(
				space.getOverlayAddress(range.getMinAddress()),
				space.getOverlayAddress(range.getMaxAddress()));
		}
		throw new AssertionError();
	}
}
