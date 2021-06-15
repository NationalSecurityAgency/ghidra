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
package ghidra.trace.database.memory;

import javax.help.UnsupportedOperationException;

import db.DBRecord;
import ghidra.program.model.address.AddressSpace;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.util.database.DBCachedObjectStore;
import ghidra.util.database.DBObjectColumn;
import ghidra.util.database.annot.*;

/**
 * INTERNAL: An entry to record memory observation states in the database
 */
@DBAnnotatedObjectInfo(version = 0)
class DBTraceMemoryStateEntry
		extends AbstractDBTraceAddressSnapRangePropertyMapData<TraceMemoryState> {

	private static final String TABLE_NAME = "MemoryState";
	static final String STATE_COLUMN_NAME = "State";

	@DBAnnotatedColumn(STATE_COLUMN_NAME)
	static DBObjectColumn STATE_COLUMN;

	static String tableName(AddressSpace space, long threadKey, int frameLevel) {
		return DBTraceUtils.tableName(TABLE_NAME, space, threadKey, frameLevel);
	}

	@DBAnnotatedField(column = STATE_COLUMN_NAME)
	private TraceMemoryState state;

	public DBTraceMemoryStateEntry(DBTraceAddressSnapRangePropertyMapTree<TraceMemoryState, ?> tree,
			DBCachedObjectStore<?> store, DBRecord record) {
		super(tree, store, record);
	}

	@Override
	protected void setRecordValue(TraceMemoryState state) {
		if (this.state != null) {
			// Prevent users from tampering with the value
			// The map will set the entry, exactly once.
			throw new UnsupportedOperationException();
		}
		this.state = state;
		update(STATE_COLUMN);
	}

	@Override
	protected TraceMemoryState getRecordValue() {
		return state;
	}
}
