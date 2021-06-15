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
package ghidra.trace.model;

import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.trace.model.map.UnsignedUtils;
import ghidra.util.database.spatial.rect.EuclideanSpace2D;

public class TraceAddressSnapSpace implements EuclideanSpace2D<Address, Long> {
	private static final Map<AddressSpace, TraceAddressSnapSpace> SPACES = new HashMap<>();

	/**
	 * Get the trace-address-snap space for a given address space
	 * 
	 * <p>
	 * Because this synchronizes on a cache of spaces, it should only be called by space
	 * constructors, never by entry constructors.
	 * 
	 * @param space the address space
	 * @return the trace-address-snap space
	 */
	public static TraceAddressSnapSpace forAddressSpace(AddressSpace space) {
		synchronized (SPACES) {
			return SPACES.computeIfAbsent(space, TraceAddressSnapSpace::new);
		}
	}

	private ImmutableTraceAddressSnapRange full;

	private TraceAddressSnapSpace(AddressSpace space) {
		this.full = new ImmutableTraceAddressSnapRange(space.getMinAddress(), space.getMaxAddress(),
			Long.MIN_VALUE, Long.MAX_VALUE, this);
	}

	@Override
	public int compareX(Address x1, Address x2) {
		return x1.compareTo(x2);
	}

	@Override
	public int compareY(Long y1, Long y2) {
		return y1.compareTo(y2);
	}

	@Override
	public double distX(Address x1, Address x2) {
		if (x2.compareTo(x1) > 0) {
			return UnsignedUtils.unsignedLongToDouble(x2.subtract(x1));
		}
		else {
			return UnsignedUtils.unsignedLongToDouble(x1.subtract(x2));
		}
	}

	@Override
	public double distY(Long y1, Long y2) {
		if (y2 == null) {
			return Double.POSITIVE_INFINITY;
		}
		if (y1 == null) {
			return Double.NEGATIVE_INFINITY;
		}
		if (y2 > y1) {
			return y2 - y1;
		}
		else {
			return y1 - y2;
		}
	}

	@Override
	public Address midX(Address x1, Address x2) {
		return x1.add(Long.divideUnsigned(x2.subtract(x1), 2));
	}

	@Override
	public Long midY(Long y1, Long y2) {
		if (y1 == null || y2 == null) {
			return null;
		}
		return y1 + (y2 - y1) / 2;
	}

	@Override
	public TraceAddressSnapRange getFull() {
		return full;
	}
}
