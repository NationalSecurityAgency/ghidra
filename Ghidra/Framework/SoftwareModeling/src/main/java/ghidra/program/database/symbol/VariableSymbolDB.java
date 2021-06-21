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
package ghidra.program.database.symbol;

import java.io.IOException;

import db.DBRecord;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.function.FunctionDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.OldGenericNamespaceAddress;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.VariableNameFieldLocation;
import ghidra.util.Lock;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Symbol class for function variables.
 *
 * Symbol Data Usage:
 *   	String stringData - variable comment
 */
public class VariableSymbolDB extends SymbolDB {

	private VariableStorage variableStorage;
	private VariableStorageManagerDB variableMgr;
	private SymbolType type;

	/**
	 * Constructs a new VariableSymbol
	 * @param symbolMgr the symbol manager
	 * @param cache symbol object cache
	 * @param type the symbol type.
	 * @param address the address of the symbol (stack address)
	 * @param record the record for the symbol
	 */
	public VariableSymbolDB(SymbolManager symbolMgr, DBObjectCache<SymbolDB> cache, SymbolType type,
			VariableStorageManagerDB variableMgr, Address address, DBRecord record) {
		super(symbolMgr, cache, address, record);
		this.type = type;
		this.variableMgr = variableMgr;
	}

	@Override
	public void setInvalid() {
		super.setInvalid();
		variableStorage = null;
	}

	public VariableStorage getVariableStorage() {
		lock.acquire();
		try {
			if (!checkIsValid() || variableStorage != null) {
				return variableStorage;
			}
			if (address instanceof OldGenericNamespaceAddress) {
				// old use case for upgrade
				try {
					variableStorage = new VariableStorage(symbolMgr.getProgram(),
						((OldGenericNamespaceAddress) address).getGlobalAddress(),
						getDataType().getLength());
				}
				catch (InvalidInputException e) {
					variableStorage = VariableStorage.BAD_STORAGE;
				}
			}
			else {
				variableStorage = variableMgr.getVariableStorage(address);
				if (variableStorage == null) {
					variableStorage = (type != SymbolType.PARAMETER) ? VariableStorage.BAD_STORAGE
							: VariableStorage.UNASSIGNED_STORAGE;
				}
			}
		}
		catch (IOException e) {
			symbolMgr.dbError(e);
		}
		finally {
			lock.release();
		}
		return variableStorage;
	}

	/**
	 * @see ghidra.program.model.symbol.Symbol#getSymbolType()
	 */
	@Override
	public SymbolType getSymbolType() {
		return type;
	}

	@Override
	protected boolean refresh(DBRecord rec) {
		boolean isValid = super.refresh(rec);
		variableStorage = null;
		return isValid;
	}

	/**
	 * @see ghidra.program.database.symbol.SymbolDB#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		// TODO: not sure what constitutes equality since address will differ
		return obj == this;
	}

	/**
	 * @see ghidra.program.model.symbol.Symbol#delete()
	 */
	@Override
	public boolean delete() {
		lock.acquire();
		try {
			if (checkIsValid()) {
				FunctionDB fun = getFunction();
				if (fun != null) {
					fun.doDeleteVariable(this);
				}
				super.delete();
				return true;
			}
			return false;
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.symbol.Symbol#getObject()
	 */
	@Override
	public Object getObject() {
		FunctionDB func = getFunction();
		if (func != null) {
			return func.getVariable(this);
		}
		return null;
	}

	/**
	 * @see ghidra.program.model.symbol.Symbol#isPrimary()
	 */
	@Override
	public boolean isPrimary() {
		return false;
	}

	@Override
	public boolean isExternal() {
		Symbol parentSymbol = getParentSymbol();
		return parentSymbol != null ? parentSymbol.isExternal() : false;
	}

	public FunctionDB getFunction() {
		return (FunctionDB) symbolMgr.getFunctionManager()
				.getFunction(
					getParentNamespace().getID());
	}

	/**
	 * @see ghidra.program.model.symbol.Symbol#getProgramLocation()
	 */
	@Override
	public ProgramLocation getProgramLocation() {
		Variable var = (Variable) getObject();
		if (var != null) {
			return new VariableNameFieldLocation(var.getProgram(), var, 0);
		}
		return null;
	}

	/**
	 * @see ghidra.program.model.symbol.Symbol#isValidParent(ghidra.program.model.symbol.Namespace)
	 */
	@Override
	public boolean isValidParent(Namespace parent) {
		return getFunction() == parent;
	}

	private String getParamName() {
		return SymbolUtilities.getDefaultParamName(getOrdinal());
	}

	@Override
	protected String doGetName() {
		if (!checkIsValid()) {
			// TODO: SCR
			return "[Invalid VariableSymbol - Deleted!]";
		}

		if (type == SymbolType.PARAMETER) {
			if (getSource() == SourceType.DEFAULT) {
				return getParamName();
			}
			String storedName = super.doGetName();
			if (SymbolUtilities.isDefaultParameterName(storedName)) {
				return getParamName();
			}
			return storedName;
		}

		VariableStorage storage = getVariableStorage();
		if (storage == null || storage.isBadStorage()) {
			return Function.DEFAULT_LOCAL_PREFIX + "_!BAD!";
		}

		if (getSource() == SourceType.DEFAULT) {
			return SymbolUtilities.getDefaultLocalName(getProgram(), storage, getFirstUseOffset());
		}

		// TODO: we use to check for a default name and regenerate new default name but we should
		// not need to do this if source remains at default

		return super.doGetName();
	}

	@Override
	protected SourceType validateNameSource(String newName, SourceType source) {
		if (SymbolUtilities.isDefaultParameterName(newName)) {
			source = SourceType.DEFAULT;
		}
		SymbolType symType = getSymbolType();
		if (symType == SymbolType.PARAMETER && SymbolUtilities.isDefaultParameterName(newName)) {
			source = SourceType.DEFAULT;
		}
		else if (symType == SymbolType.LOCAL_VAR &&
			SymbolUtilities.isDefaultLocalName(getProgram(), newName, getVariableStorage())) {
			return SourceType.DEFAULT;
		}
		return source;
	}

	public DataType getDataType() {
		DataType dt = symbolMgr.getDataType(getDataTypeId());
		if (dt == null) {
			VariableStorage storage = getVariableStorage();
			if (storage == null) {
				dt = DataType.DEFAULT;
			}
			else if (storage.isVoidStorage()) {
				dt = DataType.VOID;
			}
			else {
				dt = Undefined.getUndefinedDataType(storage.size());
			}
		}
		return dt;
	}

	/**
	 * Change the storage address and data-type associated with this
	 * variable symbol.
	 * @param newStorage
	 * @param dt data-type
	 */
	public void setStorageAndDataType(VariableStorage newStorage, DataType dt) {
		Lock myLock = symbolMgr.getLock();
		myLock.acquire();
		try {
			checkDeleted();

			long dataTypeID = symbolMgr.getProgram().getDataTypeManager().getResolvedID(dt);

			variableStorage = newStorage;
			Address newAddr = variableMgr.getVariableStorageAddress(newStorage, true);
			setAddress(newAddr); // this may be the only symbol which changes its address

			if (dataTypeID != getDataTypeId()) {
				setDataTypeId(dataTypeID);
			}
			else {
				symbolMgr.symbolDataChanged(this);
			}
		}
		catch (IOException e) {
			symbolMgr.dbError(e);
		}
		finally {
			myLock.release();
		}
	}

	public int getFirstUseOffset() {
		return type == SymbolType.PARAMETER ? 0 : getVariableOffset();
	}

	public void setFirstUseOffset(int firstUseOffset) {
		if (type == SymbolType.LOCAL_VAR) {
			setVariableOffset(firstUseOffset);
		}
	}

	public int getOrdinal() {
		return type == SymbolType.PARAMETER ? getVariableOffset() : Integer.MIN_VALUE;
	}

	public void setOrdinal(int ordinal) {
		if (type == SymbolType.PARAMETER) {
			setVariableOffset(ordinal);
		}
	}

	@Override
	public int getReferenceCount() {
		return getReferences(null).length;
	}

	@Override
	public Reference[] getReferences(TaskMonitor monitor) {
		lock.acquire();
		try {
			checkIsValid();
			ReferenceManager rm = symbolMgr.getReferenceManager();
			return rm.getReferencesTo((Variable) getObject());
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean hasMultipleReferences() {
		return getReferences(null).length > 1;
	}

	@Override
	public boolean hasReferences() {
		return getReferences(null).length != 0;
	}
}
