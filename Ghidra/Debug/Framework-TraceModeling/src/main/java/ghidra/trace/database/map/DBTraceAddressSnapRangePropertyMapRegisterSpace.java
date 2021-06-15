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
package ghidra.trace.database.map;

import java.io.IOException;
import java.util.concurrent.locks.ReadWriteLock;

import ghidra.program.model.address.AddressSpace;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMap.DBTraceAddressSnapRangePropertyMapDataFactory;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.map.TraceAddressSnapRangePropertyMapRegisterSpace;
import ghidra.util.database.DBCachedObjectStoreFactory;
import ghidra.util.exception.VersionException;

public class DBTraceAddressSnapRangePropertyMapRegisterSpace<T, DR extends AbstractDBTraceAddressSnapRangePropertyMapData<T>>
		extends DBTraceAddressSnapRangePropertyMapSpace<T, DR>
		implements TraceAddressSnapRangePropertyMapRegisterSpace<T> {
	protected final DBTraceThread thread;
	protected final int frameLevel;

	public DBTraceAddressSnapRangePropertyMapRegisterSpace(String tableName,
			DBCachedObjectStoreFactory storeFactory, ReadWriteLock lock, AddressSpace space,
			DBTraceThread thread, int frameLevel, Class<DR> dataType,
			DBTraceAddressSnapRangePropertyMapDataFactory<T, DR> dataFactory)
			throws VersionException, IOException {
		super(tableName, storeFactory, lock, space, dataType, dataFactory);
		this.thread = thread;
		this.frameLevel = frameLevel;
	}

	@Override
	public DBTraceThread getThread() {
		return thread;
	}

	@Override
	public int getFrameLevel() {
		return frameLevel;
	}
}
