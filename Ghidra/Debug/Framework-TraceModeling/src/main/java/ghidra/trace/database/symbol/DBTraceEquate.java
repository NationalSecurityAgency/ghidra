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
package ghidra.trace.database.symbol;

import java.util.Collection;

import com.google.common.collect.Range;

import db.DBRecord;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Enum;
import ghidra.program.model.pcode.Varnode;
import ghidra.trace.model.symbol.TraceEquate;
import ghidra.trace.model.symbol.TraceEquateReference;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.database.*;
import ghidra.util.database.annot.*;

@DBAnnotatedObjectInfo(version = 0)
public class DBTraceEquate extends DBAnnotatedObject implements TraceEquate {
	public static final String TABLE_NAME = "Equates";

	static final String NAME_COLUMN_NAME = "Name";
	static final String VALUE_COLUMN_NAME = "Value";

	@DBAnnotatedColumn(NAME_COLUMN_NAME)
	static DBObjectColumn NAME_COLUMN;
	@DBAnnotatedColumn(VALUE_COLUMN_NAME)
	static DBObjectColumn VALUE_COLUMN;

	@DBAnnotatedField(column = NAME_COLUMN_NAME, indexed = true)
	private String name;
	@DBAnnotatedField(column = VALUE_COLUMN_NAME, indexed = true)
	private long value;

	protected final DBTraceEquateManager manager;

	public DBTraceEquate(DBTraceEquateManager manager, DBCachedObjectStore<DBTraceEquate> store,
			DBRecord record) {
		super(store, record);
		this.manager = manager;
	}

	void set(String name, long value) {
		this.name = name;
		this.value = value;
		update(NAME_COLUMN, VALUE_COLUMN);
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public long getValue() {
		return value;
	}

	@Override
	public String getDisplayName() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getDisplayValue() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public int getReferenceCount() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public TraceEquateReference addReference(Range<Long> lifespan, TraceThread thread,
			Address address, int operandIndex) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public TraceEquateReference addReference(Range<Long> lifespan, TraceThread thread,
			Address address, Varnode varnode) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void setName(String newName) {
		// TODO Auto-generated method stub

	}

	@Override
	public Collection<? extends TraceEquateReference> getReferences() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public TraceEquateReference getReference(long snap, TraceThread thread, Address address,
			int operandIndex) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public TraceEquateReference getReference(long snap, TraceThread thread, Address address,
			Varnode varnode) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean hasValidEnum() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isEnumBased() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Enum getEnum() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void delete() {
		// TODO: Delete all references to me
		manager.doDelete(this);
	}
}
