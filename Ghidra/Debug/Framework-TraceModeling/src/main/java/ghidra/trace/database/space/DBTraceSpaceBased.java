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
package ghidra.trace.database.space;

import com.google.common.collect.Range;
import com.google.common.primitives.UnsignedLong;

import ghidra.program.model.address.*;

public interface DBTraceSpaceBased extends DBTraceSpaceKey {
	default long assertInSpace(Address addr) {
		if (addr.getAddressSpace() != getAddressSpace()) {
			throw new IllegalArgumentException(
				"Address '" + addr + "' is not in this space: '" + getAddressSpace() + "'");
		}
		return addr.getOffset();
	}

	default void assertInSpace(AddressRange range) {
		if (range.getAddressSpace() != getAddressSpace()) {
			throw new IllegalArgumentException(
				"Address Range '" + range + "' is not in this space: '" + getAddressSpace() + "'");
		}
	}

	default UnsignedLong toOffset(Address address) {
		return UnsignedLong.fromLongBits(address.getOffset());
	}

	default Range<UnsignedLong> toOffsetRange(AddressRange range) {
		return Range.closed(toOffset(range.getMinAddress()), toOffset(range.getMaxAddress()));
	}

	default Address toAddress(UnsignedLong offset) {
		return getAddressSpace().getAddress(offset.longValue());
	}

	default Address toAddress(long offset) {
		return getAddressSpace().getAddress(offset);
	}

	default AddressRange toAddressRange(Range<UnsignedLong> range) {
		return new AddressRangeImpl(toAddress(range.lowerEndpoint()),
			toAddress(range.upperEndpoint()));
	}

	void invalidateCache();
}
