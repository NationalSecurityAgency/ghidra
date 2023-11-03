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
package ghidra.trace.database.target;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.Lifespan;
import ghidra.util.database.DBCachedObjectStoreFactory.RecAddress;

public record ImmutableValueShape(DBTraceObject parent, DBTraceObject child, String entryKey,
		Lifespan lifespan, int addressSpaceId, long minAddressOffset, long maxAddressOffset)
		implements ValueShape {

	public static int getAddressSpaceId(Object value) {
		if (value instanceof Address address) {
			return address.getAddressSpace().getSpaceID();
		}
		if (value instanceof AddressRange range) {
			return range.getAddressSpace().getSpaceID();
		}
		return -1;
	}

	public static long getMinAddressOffset(Object value) {
		if (value instanceof Address address) {
			return address.getOffset();
		}
		if (value instanceof AddressRange range) {
			return range.getMinAddress().getOffset();
		}
		return 0;
	}

	public static long getMaxAddressOffset(Object value) {
		if (value instanceof Address address) {
			return address.getOffset();
		}
		if (value instanceof AddressRange range) {
			return range.getMaxAddress().getOffset();
		}
		return 0;
	}

	public ImmutableValueShape(DBTraceObject parent, Object value, String entryKey,
			Lifespan lifespan) {
		this(parent, value instanceof DBTraceObject child ? child : null, entryKey, lifespan,
			getAddressSpaceId(value), getMinAddressOffset(value), getMaxAddressOffset(value));
	}

	public ImmutableValueShape(ValueShape shape) {
		this(shape.getParent(), shape.getChildOrNull(), shape.getEntryKey(), shape.getLifespan(),
			shape.getAddressSpaceId(), shape.getMinAddressOffset(), shape.getMaxAddressOffset());
	}

	@Override
	public ValueBox getBounds() {
		long parentKey = parent == null ? -1 : parent.getKey();
		long childKey = child == null ? -1 : child.getKey();
		return new ImmutableValueBox(
			new ValueTriple(parentKey, childKey, entryKey, lifespan.lmin(),
				new RecAddress(addressSpaceId, minAddressOffset)),
			new ValueTriple(parentKey, childKey, entryKey, lifespan.lmax(),
				new RecAddress(addressSpaceId, maxAddressOffset)));
	}

	@Override
	public String description() {
		return toString();
	}

	@Override
	public DBTraceObject getParent() {
		return parent;
	}

	@Override
	public DBTraceObject getChild() {
		return child;
	}

	@Override
	public DBTraceObject getChildOrNull() {
		return child;
	}

	@Override
	public String getEntryKey() {
		return entryKey;
	}

	@Override
	public Lifespan getLifespan() {
		return lifespan;
	}

	@Override
	public int getAddressSpaceId() {
		return addressSpaceId;
	}

	@Override
	public long getMinAddressOffset() {
		return minAddressOffset;
	}

	@Override
	public long getMaxAddressOffset() {
		return maxAddressOffset;
	}
}
