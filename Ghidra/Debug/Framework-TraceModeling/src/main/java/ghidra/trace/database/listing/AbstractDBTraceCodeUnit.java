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
package ghidra.trace.database.listing;

import java.nio.ByteBuffer;

import db.DBRecord;
import ghidra.program.model.address.Address;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData;
import ghidra.trace.database.memory.DBTraceMemorySpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceAddressSpace;
import ghidra.util.LockHold;
import ghidra.util.database.DBCachedObjectStore;

public abstract class AbstractDBTraceCodeUnit<T extends AbstractDBTraceCodeUnit<T>> extends
		AbstractDBTraceAddressSnapRangePropertyMapData<T> implements DBTraceCodeUnitAdapter {

	protected final DBTraceCodeSpace space;

	protected ByteBuffer byteCache; // NOTE: Memory cannot be changed under a code unit

	public AbstractDBTraceCodeUnit(DBTraceCodeSpace space,
			DBTraceAddressSnapRangePropertyMapTree<T, ?> tree, DBCachedObjectStore<?> store,
			DBRecord record) {
		super(tree, store, record);
		this.space = space;
	}

	@Override
	public TraceAddressSpace getTraceSpace() {
		return space;
	}

	@Override
	public Address getAddress() {
		return getX1();
	}

	@Override
	public Address getMaxAddress() {
		return getX2();
	}

	@Override
	public int getLength() {
		return (int) range.getLength();
	}

	@Override
	public TraceThread getThread() {
		return space.getThread();
	}

	@Override
	public DBTrace getTrace() {
		return space.trace;
	}

	@Override
	public long getStartSnap() {
		return getY1();
	}

	@Override
	public void setEndSnap(long endSnap) {
		doSetLifespan(DBTraceUtils.toRange(DBTraceUtils.lowerEndpoint(lifespan), endSnap));
	}

	@Override
	public long getEndSnap() {
		return getY2();
	}

	// TODO: Ensure this is tested with various offsets, including within the passed buffer
	@Override
	public int getBytes(ByteBuffer buffer, int addressOffset) {
		try (LockHold hold = space.trace.lockRead()) {
			Address address = getX1();
			if (byteCache == null) {
				byteCache = ByteBuffer.allocate(getLength());
			}
			int end = addressOffset + buffer.remaining();
			// Fill the cache, if needed
			if (end > byteCache.position()) {
				byteCache.limit(Math.min(byteCache.capacity(), end));
				// TODO: Retrieve the memory space at code space construction time
				DBTraceMemorySpace mem = space.trace.getMemoryManager().get(space, false);
				mem.getViewBytes(getStartSnap(), address.add(byteCache.position()), byteCache);
			}
			// Copy from the cache
			int toCopyFromCache =
				Math.max(0, Math.min(byteCache.position() - addressOffset, buffer.remaining()));
			buffer.put(byteCache.array(), addressOffset, toCopyFromCache);
			if (byteCache.position() >= end) {
				return toCopyFromCache;
			}
			// If needed, copy the rest from DB
			assert byteCache.position() == byteCache.capacity();
			int startRemains = Math.max(addressOffset, byteCache.position());
			DBTraceMemorySpace mem = space.trace.getMemoryManager().get(space, false);
			return toCopyFromCache +
				mem.getViewBytes(getStartSnap(), address.add(startRemains), buffer);
		}
	}
}
