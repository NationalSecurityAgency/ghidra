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

import db.DBRecord;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolType;
import ghidra.trace.model.Trace.TraceFunctionChangeType;
import ghidra.trace.model.symbol.TraceLocalVariableSymbol;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;
import ghidra.util.database.DBCachedObjectStore;
import ghidra.util.database.DBObjectColumn;
import ghidra.util.database.annot.*;

@DBAnnotatedObjectInfo(version = 0)
public class DBTraceLocalVariableSymbol extends AbstractDBTraceVariableSymbol
		implements TraceLocalVariableSymbol {
	static final String TABLE_NAME = "LocalVars";

	static final String FIRST_USE_COLUMN_NAME = "FirstUse";

	@DBAnnotatedColumn(FIRST_USE_COLUMN_NAME)
	static DBObjectColumn FIRST_USE_COLUMN;

	@DBAnnotatedField(column = FIRST_USE_COLUMN_NAME)
	int firstUseOffset;

	public DBTraceLocalVariableSymbol(DBTraceSymbolManager manager, DBCachedObjectStore<?> store,
			DBRecord record) {
		super(manager, store, record);
	}

	protected void set(String name, DBTraceFunctionSymbol function, DataType dt,
			VariableStorage storage, int firstUseOffset, SourceType source) {
		super.set(name, function, dt, storage, source);
		this.firstUseOffset = firstUseOffset;
		update(FIRST_USE_COLUMN);
	}

	@Override
	public SymbolType getSymbolType() {
		return SymbolType.LOCAL_VAR;
	}

	@Override
	public DBTraceFunctionSymbol getParentNamespace() {
		return (DBTraceFunctionSymbol) super.getParentNamespace();
	}

	@Override
	public DBTraceFunctionSymbol getParentSymbol() {
		return (DBTraceFunctionSymbol) super.getParentSymbol();
	}

	@Override
	public DBTraceFunctionSymbol getFunction() {
		return getParentSymbol();
	}

	@Override
	public boolean setPrimary() {
		return false;
	}

	@Override
	public boolean isPrimary() {
		return false;
	}

	@Override
	public boolean setFirstUseOffset(int firstUseOffset) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			if (this.firstUseOffset == firstUseOffset) {
				return true; // ineffective, but successful
			}
			this.firstUseOffset = firstUseOffset;
			update(FIRST_USE_COLUMN);
		}
		manager.trace.setChanged(
			new TraceChangeRecord<>(TraceFunctionChangeType.CHANGED, getSpace(), getFunction()));
		return true;
	}

	@Override
	public int getFirstUseOffset() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			return firstUseOffset;
		}
	}

	@Override
	protected void doUpdatesAfterSetDataType() {
		super.doUpdatesAfterSetDataType();
		manager.trace.setChanged(
			new TraceChangeRecord<>(TraceFunctionChangeType.CHANGED, getSpace(), getFunction()));
	}

	@Override
	public boolean delete() {
		if (super.delete()) {
			manager.trace.setChanged(new TraceChangeRecord<>(TraceFunctionChangeType.CHANGED,
				getSpace(), getFunction()));
			return true;
		}
		return false;
	}
}
