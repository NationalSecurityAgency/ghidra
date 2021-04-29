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

import com.google.common.collect.Range;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.database.DBTraceUtils;
import ghidra.util.database.spatial.rect.Rectangle2D;

public interface TraceAddressSnapRange extends Rectangle2D<Address, Long, TraceAddressSnapRange> {
	Range<Long> getLifespan();

	AddressRange getRange();

	@Override
	default TraceAddressSnapRange getBounds() {
		return this;
	}

	@Override
	default Address getX1() {
		return getRange().getMinAddress();
	}

	@Override
	default Address getX2() {
		return getRange().getMaxAddress();
	}

	@Override
	default Long getY1() {
		return DBTraceUtils.lowerEndpoint(getLifespan());
	}

	@Override
	default Long getY2() {
		return DBTraceUtils.upperEndpoint(getLifespan());
	}

	@Override
	default TraceAddressSnapRange immutable(Address x1, Address x2, Long y1, Long y2) {
		return new ImmutableTraceAddressSnapRange(x1, x2, y1, y2);
	}

	@Override
	default String description() {
		return String.format("[%s:%x:%x]%s", getRange().getAddressSpace(), getX1().getOffset(),
			getX2().getOffset(), getLifespan());
	}
}
