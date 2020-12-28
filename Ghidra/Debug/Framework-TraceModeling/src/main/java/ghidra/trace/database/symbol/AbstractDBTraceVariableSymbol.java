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

import java.io.IOException;
import java.util.List;
import java.util.Objects;

import db.DBRecord;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.trace.database.symbol.DBTraceSymbolManager.DBTraceVariableStorageEntry;
import ghidra.trace.model.Trace.TraceSymbolChangeType;
import ghidra.trace.model.symbol.TraceVariableSymbol;
import ghidra.util.LockHold;
import ghidra.util.database.DBCachedObjectStore;
import ghidra.util.database.DBObjectColumn;
import ghidra.util.database.annot.DBAnnotatedColumn;
import ghidra.util.database.annot.DBAnnotatedField;
import ghidra.util.exception.InvalidInputException;

/**
 * TODO: Document me
 * 
 * TODO: Somehow, this is supposed to generate {@link TraceSymbolChangeType#ADDRESS_CHANGED}. Find
 * out how and be sure to implement it.
 */
public abstract class AbstractDBTraceVariableSymbol extends AbstractDBTraceSymbol
		implements TraceVariableSymbol {

	static final String DATATYPE_COLUMN_NAME = "DataType";
	static final String STORAGE_COLUMN_NAME = "Storage";
	static final String COMMENT_COLUMN_NAME = "Comment";

	@DBAnnotatedColumn(DATATYPE_COLUMN_NAME)
	static DBObjectColumn DATATYPE_COLUMN;
	@DBAnnotatedColumn(STORAGE_COLUMN_NAME)
	static DBObjectColumn STORAGE_COLUMN;
	@DBAnnotatedColumn(COMMENT_COLUMN_NAME)
	static DBObjectColumn COMMENT_COLUMN;

	@DBAnnotatedField(column = DATATYPE_COLUMN_NAME)
	private long dataTypeID;
	@DBAnnotatedField(column = STORAGE_COLUMN_NAME)
	private int storageID;
	@DBAnnotatedField(column = COMMENT_COLUMN_NAME)
	private String comment;

	protected DataType dataType;
	protected VariableStorage storage;
	protected Address address;

	public AbstractDBTraceVariableSymbol(DBTraceSymbolManager manager, DBCachedObjectStore<?> store,
			DBRecord record) {
		super(manager, store, record);
	}

	@Override
	protected void fresh(boolean created) throws IOException {
		super.fresh(created);
		if (created) {
			return;
		}
		dataType = manager.dataTypeManager.getDataType(dataTypeID);
		DBTraceVariableStorageEntry storageEntry = manager.storageStore.getObjectAt(storageID);
		if (storageEntry == null) {
			throw new IOException(
				"Database is corrupt. Cannot find VariableStorage entry " + storageID);
		}
		storage = storageEntry.getStorage();
		address = AddressSpace.VARIABLE_SPACE.getAddress(storageID);
	}

	protected void set(String name, DBTraceNamespaceSymbol parent, DataType dt,
			VariableStorage storage, SourceType source) {
		super.set(name, parent, source);
		this.dataTypeID = manager.dataTypeManager.getResolvedID(dt);
		this.dataType = manager.dataTypeManager.getDataType(dataTypeID);
		this.storageID = manager.findOrRecordVariableStorage(storage);
		update(DATATYPE_COLUMN, STORAGE_COLUMN);

		this.storage = storage;
		this.address = AddressSpace.VARIABLE_SPACE.getAddress(storageID);
	}

	protected VariableStorage adjustStorage(VariableStorage s) {
		return s;
	}

	@Override
	public String toString() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			return String.format("[%s %s@%s]", getDataType().getName(), getName(),
				getVariableStorage());
		}
	}

	@Override
	public Address getAddress() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			return address;
		}
	}

	@Override
	public Object getObject() {
		return this;
	}

	@Override
	public Symbol getSymbol() {
		return this;
	}

	@Override
	public int getLength() {
		return getDataType().getLength();
	}

	@Override
	public boolean isValid() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			VariableStorage s = getVariableStorage(); // Overridden by DBTraceParameterSymbol
			if (!s.isValid()) {
				return false;
			}
			if (dataType instanceof AbstractFloatDataType) {
				return true;
			}
			// NOTE: Use getDataType(), since storage may force indirection (pointer)
			return s.size() == getDataType().getLength();
		}
	}

	protected void doSetDataType(DataType dt) {
		this.dataTypeID = manager.dataTypeManager.getResolvedID(dt);
		this.dataType = manager.dataTypeManager.getDataType(dataTypeID);
		update(DATATYPE_COLUMN);
	}

	protected void doSetStorage(VariableStorage s) {
		this.storage = s;
		update(STORAGE_COLUMN);
	}

	// NOTE: Must have the write lock
	protected void doSetStorageAndDataType(VariableStorage s, DataType dt) {
		doSetDataType(dt);
		doSetStorage(adjustStorage(s));
	}

	protected void doUpdatesAfterSetDataType() {
		// Extension point
	}

	@Override
	public void setDataType(DataType dt, VariableStorage s, boolean force, SourceType source)
			throws InvalidInputException {
		s = adjustStorage(s);
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			dt = VariableUtilities.checkDataType(dt, false, getLength(), getProgram());
			// NOTE: UNASSIGNED passes through
			DBTraceFunctionSymbol function = getFunction();
			s = VariableUtilities.checkStorage(function, s, dt, force);
			VariableUtilities.checkVariableConflict(function, this, s, force);
			doSetStorageAndDataType(s, dt);
			doUpdatesAfterSetDataType();
		}
	}

	protected VariableStorage doDeriveStorageForSetDataType(DataType dt, boolean alignStack,
			boolean force) throws InvalidInputException {
		try {
			VariableStorage s = VariableUtilities.resizeStorage(getVariableStorage(), dt,
				alignStack, getFunction());
			VariableUtilities.checkStorage(s, dt, force);
			VariableUtilities.checkVariableConflict(getFunction(), this, s, force);
			return s;
		}
		catch (InvalidInputException e) {
			if (!force) {
				throw e;
			}
			return VariableStorage.UNASSIGNED_STORAGE;
		}
	}

	@Override
	public void setDataType(DataType dt, boolean alignStack, boolean force, SourceType source)
			throws InvalidInputException {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			dt = VariableUtilities.checkDataType(dt, false, getLength(), getProgram());
			VariableStorage s = doDeriveStorageForSetDataType(dt, alignStack, force);
			doSetStorageAndDataType(s, dt);
			doUpdatesAfterSetDataType();
		}
	}

	@Override
	public void setDataType(DataType dt, SourceType source) throws InvalidInputException {
		setDataType(dt, true, false, source);
	}

	@Override
	public DataType getDataType() {
		return dataType;
	}

	@Override
	public abstract DBTraceFunctionSymbol getFunction();

	@Override
	public void setComment(String comment) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			this.comment = comment;
			update(COMMENT_COLUMN);
		}
	}

	@Override
	public String getComment() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			return comment;
		}
	}

	@Override
	public VariableStorage getVariableStorage() {
		return storage;
	}

	@Override
	public Varnode getFirstStorageVarnode() {
		VariableStorage s = getVariableStorage();
		return s == null ? null : s.getFirstVarnode();
	}

	@Override
	public Varnode getLastStorageVarnode() {
		VariableStorage s = getVariableStorage();
		return s == null ? null : s.getLastVarnode();
	}

	@Override
	public boolean isStackVariable() {
		VariableStorage s = getVariableStorage();
		return s == null ? false : s.isStackStorage();
	}

	@Override
	public boolean hasStackStorage() {
		VariableStorage s = getVariableStorage();
		return s == null ? false : s.hasStackStorage();
	}

	@Override
	public boolean isRegisterVariable() {
		VariableStorage s = getVariableStorage();
		return s == null ? false : s.isRegisterStorage();
	}

	@Override
	public Register getRegister() {
		VariableStorage s = getVariableStorage();
		return s == null ? null : s.getRegister();
	}

	@Override
	public List<Register> getRegisters() {
		VariableStorage s = getVariableStorage();
		return s == null ? null : s.getRegisters();
	}

	@Override
	public Address getMinAddress() {
		VariableStorage s = getVariableStorage();
		return s == null ? null : s.getMinAddress();
	}

	@Override
	public int getStackOffset() {
		VariableStorage s = getVariableStorage();
		if (s == null) {
			throw new UnsupportedOperationException("Variable has no storage");
		}
		return s.getStackOffset();
	}

	@Override
	public boolean isMemoryVariable() {
		VariableStorage s = getVariableStorage();
		return s == null ? false : s.isMemoryStorage();
	}

	@Override
	public boolean isUniqueVariable() {
		VariableStorage s = getVariableStorage();
		return s == null ? false : s.isHashStorage();
	}

	@Override
	public boolean isCompoundVariable() {
		VariableStorage s = getVariableStorage();
		return s == null ? false : s.isCompoundStorage();
	}

	@Override
	public boolean hasAssignedStorage() {
		VariableStorage s = getVariableStorage();
		return s == null ? false : !s.isUnassignedStorage();
	}

	protected static boolean doHasCustomStorage(Variable v) {
		Function f = v.getFunction();
		return f == null || f.hasCustomVariableStorage();
	}

	public static boolean areEquivalent(Variable v1, Variable v2) {
		if (v1 == null && v2 == null) {
			return true;
		}
		if (v1 == null || v2 == null) {
			return false;
		}
		if (v1 == v2) {
			return true;
		}
		if ((v1 instanceof Parameter) != (v2 instanceof Parameter)) {
			return false;
		}
		if (v1 instanceof Parameter) {
			Parameter p1 = (Parameter) v1;
			Parameter p2 = (Parameter) v2;
			if (p1.getOrdinal() != p2.getOrdinal()) {
				return false;
			}
		}
		if (v1.getFirstUseOffset() != v2.getFirstUseOffset()) {
			return false;
		}
		boolean eitherCustom = doHasCustomStorage(v1) || doHasCustomStorage(v2);
		if (eitherCustom && !Objects.equals(v1.getVariableStorage(), v2.getVariableStorage())) {
			return false;
		}
		if (!DataTypeUtilities.isSameOrEquivalentDataType(v1.getDataType(), v2.getDataType())) {
			return false;
		}
		return true;
	}

	@Override
	public boolean isEquivalent(Variable variable) {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			return areEquivalent(this, variable);
		}
	}

	@Override
	public int compareTo(Variable that) {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			return VariableUtilities.compare(this, that);
		}
	}

	@Override
	public boolean delete() {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			DBTraceFunctionSymbol function = getFunction();
			if (function != null) {
				function.doDeleteVariable(this);
			}
			return super.delete();
		}
	}
}
