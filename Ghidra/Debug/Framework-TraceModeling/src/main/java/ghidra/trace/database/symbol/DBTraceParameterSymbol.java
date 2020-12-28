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

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import db.DBRecord;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.trace.model.Trace.TraceFunctionChangeType;
import ghidra.trace.model.symbol.TraceParameterSymbol;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;
import ghidra.util.database.DBCachedObjectStore;
import ghidra.util.database.DBObjectColumn;
import ghidra.util.database.annot.*;
import ghidra.util.exception.InvalidInputException;

@DBAnnotatedObjectInfo(version = 0)
public class DBTraceParameterSymbol extends AbstractDBTraceVariableSymbol
		implements TraceParameterSymbol {
	static final String TABLE_NAME = "Parameters";

	static final String ORDINAL_COLUMN_NAME = "Ordinal";

	@DBAnnotatedColumn(ORDINAL_COLUMN_NAME)
	static DBObjectColumn ORDINAL_COLUMN;

	@DBAnnotatedField(column = ORDINAL_COLUMN_NAME)
	int ordinal;

	// This is transient, when the function does not use custom parameter storage.
	// It is unused if the function uses custom storage.
	protected VariableStorage dynamicStorage = VariableStorage.UNASSIGNED_STORAGE;

	public DBTraceParameterSymbol(DBTraceSymbolManager manager, DBCachedObjectStore<?> store,
			DBRecord record) {
		super(manager, store, record);
	}

	protected void set(String name, DBTraceFunctionSymbol function, DataType dt,
			VariableStorage storage, int ordinal, SourceType source) {
		super.set(name, function, dt, storage, source);
		this.ordinal = ordinal;
		update(ORDINAL_COLUMN);
	}

	@Override
	protected VariableStorage adjustStorage(VariableStorage s) {
		if (!getFunction().hasCustomVariableStorage()) {
			return VariableStorage.UNASSIGNED_STORAGE;
		}
		return super.adjustStorage(s);
	}

	@Override
	public SymbolType getSymbolType() {
		return SymbolType.PARAMETER;
	}

	@Override
	protected Pair<String, SourceType> validateNameAndSource(String newName, SourceType newSource)
			throws InvalidInputException {
		if (newSource == SourceType.DEFAULT || newName == null || "".equals(newName) ||
			SymbolUtilities.isDefaultParameterName(newName)) {
			return new ImmutablePair<>("", SourceType.DEFAULT);
		}
		return new ImmutablePair<>(newName, newSource);
	}

	@Override
	public String getName() {
		if (getSource() == SourceType.DEFAULT && ordinal != -1) {
			return SymbolUtilities.getDefaultParamName(ordinal);
		}
		return super.getName();
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
	public VariableStorage getVariableStorage() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			if (!getFunction().hasCustomVariableStorage()) {
				return dynamicStorage;
			}
			return super.getVariableStorage();
		}
	}

	// Internal
	public void setOrdinal(int ordinal) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			this.ordinal = ordinal;
			update(ORDINAL_COLUMN);
		}
	}

	@Override
	public int getOrdinal() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			return ordinal;
		}
	}

	@Override
	public boolean isAutoParameter() {
		return false;
	}

	@Override
	public AutoParameterType getAutoParameterType() {
		return null;
	}

	@Override
	public boolean isForcedIndirect() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			VariableStorage s = getVariableStorage();
			return s == null ? false : s.isForcedIndirect();
		}
	}

	@Override
	public DataType getDataType() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			return manager.checkIndirection(getVariableStorage(), getFormalDataType());
		}
	}

	@Override
	public DataType getFormalDataType() {
		return super.getDataType();
	}

	@Override
	public int getFirstUseOffset() {
		return 0;
	}

	protected void doSetDynamicStorage(VariableStorage s) {
		assert !getFunction().hasCustomVariableStorage();
		this.dynamicStorage = s;
	}

	@Override
	protected void doUpdatesAfterSetDataType() {
		super.doUpdatesAfterSetDataType();
		DBTraceFunctionSymbol function = getFunction();
		if (!function.hasCustomVariableStorage()) {
			function.doUpdateParametersAndReturn();
		}
		function.doUpdateSignatureSourceAfterVariableChange(getSource(), getDataType());
		if (ordinal == Parameter.RETURN_ORIDINAL) {
			manager.trace.setChanged(new TraceChangeRecord<>(TraceFunctionChangeType.CHANGED_RETURN,
				getSpace(), getFunction()));
		}
		else {
			manager.trace.setChanged(new TraceChangeRecord<>(
				TraceFunctionChangeType.CHANGED_PARAMETERS, getSpace(), getFunction()));
		}
	}

	@Override
	protected VariableStorage doDeriveStorageForSetDataType(DataType dt, boolean alignStack,
			boolean force) throws InvalidInputException {
		if (!getFunction().hasCustomVariableStorage()) {
			return VariableStorage.UNASSIGNED_STORAGE;
		}
		return super.doDeriveStorageForSetDataType(dt, alignStack, force);
	}

	@Override
	public boolean delete() {
		if (super.delete()) {
			manager.trace.setChanged(new TraceChangeRecord<>(
				TraceFunctionChangeType.CHANGED_PARAMETERS, getSpace(), getFunction()));
			return true;
		}
		return false;
	}
}
