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
package ghidra.program.database.function;

import java.util.List;

import org.apache.commons.lang3.StringUtils;

import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.database.symbol.SymbolDB;
import ghidra.program.database.symbol.VariableSymbolDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Database implementation of a Variable. 
 *
 */
public abstract class VariableDB implements Variable {

	// TODO: Should this be a DBObject ?

	protected VariableSymbolDB symbol;
	protected VariableStorage storage;
	protected FunctionDB function;
	protected FunctionManagerDB functionMgr;

	VariableDB(FunctionDB function, SymbolDB s) {
		this.symbol = (VariableSymbolDB) s;
		this.function = function;
		this.functionMgr = function.getFunctionManager();
	}

	@Override
	public boolean isValid() {
		VariableStorage variableStorage = getVariableStorage();
		DataType dt = getDataType();
		return variableStorage.isValid() &&
			((dt instanceof AbstractFloatDataType) || variableStorage.size() == dt.getLength());
	}

	@Override
	public Program getProgram() {
		return function.getProgram();
	}

	@Override
	public DataType getDataType() {
		return symbol.getDataType();
	}

	@Override
	public void setDataType(DataType type, VariableStorage newStorage, boolean force,
			SourceType source) throws InvalidInputException, VariableSizeException {
		functionMgr.lock.acquire();
		try {
			function.startUpdate();
			function.checkDeleted();
			if ((this instanceof Parameter) && !function.hasCustomVariableStorage()) {
				newStorage = VariableStorage.UNASSIGNED_STORAGE;
			}
			// TODO: Is there concern about variable no longer be contained within function?
			type = VariableUtilities.checkDataType(type, false, getLength(), function.getProgram());
			if (!(this instanceof Parameter) || function.hasCustomVariableStorage()) {
				newStorage = VariableUtilities.checkStorage(function, newStorage, type, force);
				VariableUtilities.checkVariableConflict(function, this, newStorage, force);
				setStorageAndDataType(newStorage, type);
			}
			else {
				setStorageAndDataType(newStorage, type);
				function.updateParametersAndReturn();
			}
			if (this instanceof Parameter) {
				function.updateSignatureSourceAfterVariableChange(source, type);
			}
			// VARDO: what if we only have changed storage and not datatype - different event?
			function.dataTypeChanged(this);
		}
		finally {
			function.endUpdate();
			functionMgr.lock.release();
		}
	}

	@Override
	public void setDataType(DataType type, boolean alignStack, boolean force, SourceType source)
			throws InvalidInputException {
		functionMgr.lock.acquire();
		try {
			function.startUpdate();
			function.checkDeleted();
			// VARDO: Is there concern about variable no longer be contained within function?
			type = VariableUtilities.checkDataType(type, false, getLength(), function.getProgram());
			VariableStorage newStorage = VariableStorage.UNASSIGNED_STORAGE;
			if (!(this instanceof Parameter) || function.hasCustomVariableStorage()) {
				try {
					newStorage = VariableUtilities.resizeStorage(getVariableStorage(), type,
						alignStack, function);
					VariableUtilities.checkStorage(newStorage, type, force);
					VariableUtilities.checkVariableConflict(function, this, newStorage, force);
				}
				catch (InvalidInputException e) {
					if (!force) {
						throw e;
					}
					newStorage = VariableStorage.UNASSIGNED_STORAGE;
				}
				setStorageAndDataType(newStorage, type);
			}
			else {
				setStorageAndDataType(newStorage, type);
				function.updateParametersAndReturn();
			}
			if (this instanceof Parameter) {
				function.updateSignatureSourceAfterVariableChange(source, type);
			}
			function.dataTypeChanged(this);
		}
		finally {
			function.endUpdate();
			functionMgr.lock.release();
		}
	}

	@Override
	public void setDataType(DataType type, SourceType source) throws InvalidInputException {
		setDataType(type, true, false, source);
	}

	@Override
	public String getName() {
		return symbol.getName();
	}

	@Override
	public int getLength() {
		return getDataType().getLength();
	}

	@Override
	public void setName(String name, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		symbol.setName(name, source);
	}

	@Override
	public String getComment() {
		return symbol.getSymbolData3();
	}

	@Override
	public void setComment(String comment) {
		symbol.setSymbolData3(comment);
		functionMgr.functionChanged(function, 0);
	}

	@Override
	public Function getFunction() {
		return function;
	}

	@Override
	public Symbol getSymbol() {
		return symbol;
	}

	@Override
	public String toString() {
		StringBuilder strBuilder = new StringBuilder();
		strBuilder.append("[");
		strBuilder.append(getDataType().getName());
		strBuilder.append(" ");
		strBuilder.append(getName());
		strBuilder.append("@");
		strBuilder.append(getVariableStorage().toString());
		strBuilder.append("]");
		return strBuilder.toString();
	}

	@Override
	public SourceType getSource() {
		return symbol.getSource();
	}

	@Override
	public boolean hasAssignedStorage() {
		return !symbol.getVariableStorage().isUnassignedStorage();
	}

	@Override
	public VariableStorage getVariableStorage() {
		if (storage == null) {
			// lazy storage is for custom storage only - dynamic parameter storage must be maintained
			storage = symbol.getVariableStorage();
		}
		return storage;
	}

	void setDynamicStorage(VariableStorage storage) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Varnode getFirstStorageVarnode() {
		VariableStorage variableStorage = getVariableStorage();
		if (variableStorage != null) {
			return variableStorage.getFirstVarnode();
		}
		return null;
	}

	@Override
	public Varnode getLastStorageVarnode() {
		VariableStorage variableStorage = getVariableStorage();
		if (variableStorage != null) {
			return variableStorage.getLastVarnode();
		}
		return null;
	}

	@Override
	public boolean isStackVariable() {
		VariableStorage variableStorage = getVariableStorage();
		if (variableStorage != null) {
			return variableStorage.isStackStorage();
		}
		return false;
	}

	@Override
	public boolean hasStackStorage() {
		VariableStorage variableStorage = getVariableStorage();
		if (variableStorage != null) {
			return variableStorage.hasStackStorage();
		}
		return false;
	}

	@Override
	public boolean isRegisterVariable() {
		VariableStorage variableStorage = getVariableStorage();
		if (variableStorage != null) {
			return variableStorage.isRegisterStorage();
		}
		return false;
	}

	@Override
	public Register getRegister() {
		VariableStorage variableStorage = getVariableStorage();
		if (variableStorage != null) {
			return variableStorage.getRegister();
		}
		return null;
	}

	@Override
	public List<Register> getRegisters() {
		VariableStorage variableStorage = getVariableStorage();
		if (variableStorage != null) {
			return variableStorage.getRegisters();
		}
		return null;
	}

	@Override
	public Address getMinAddress() {
		VariableStorage variableStorage = getVariableStorage();
		if (variableStorage != null) {
			return variableStorage.getMinAddress();
		}
		return null;
	}

	@Override
	public int getStackOffset() {
		VariableStorage variableStorage = getVariableStorage();
		if (variableStorage != null) {
			return variableStorage.getStackOffset();
		}
		throw new UnsupportedOperationException("Variable is not a stack variable");
	}

	@Override
	public boolean isMemoryVariable() {
		VariableStorage variableStorage = getVariableStorage();
		if (variableStorage != null) {
			return variableStorage.isMemoryStorage();
		}
		return false;
	}

	@Override
	public boolean isUniqueVariable() {
		VariableStorage variableStorage = getVariableStorage();
		if (variableStorage != null) {
			return variableStorage.isHashStorage();
		}
		return false;
	}

	@Override
	public boolean isCompoundVariable() {
		VariableStorage variableStorage = getVariableStorage();
		return variableStorage != null && variableStorage.isCompoundStorage();
	}

	@Override
	public int hashCode() {
		int hashcode = getFirstUseOffset();
		hashcode ^= getVariableStorage().hashCode();
		return hashcode;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}
		if (!(obj instanceof Variable)) {
			return false;
		}

		Variable otherVar = (Variable) obj;

		if (!isEquivalent(otherVar)) {
			return false;
		}
		if (!StringUtils.equals(getName(), otherVar.getName())) {
			return false;
		}
		return StringUtils.equals(getComment(), otherVar.getComment());
	}

	@Override
	public int compareTo(Variable otherVar) {
		return VariableUtilities.compare(this, otherVar);
	}

	@Override
	public boolean isEquivalent(Variable otherVar) {
		if (otherVar == null) {
			return false;
		}
		if (otherVar == this) {
			return true;
		}
		if ((otherVar instanceof Parameter) != (this instanceof Parameter)) {
			return false;
		}
		if ((this instanceof Parameter) &&
			((Parameter) this).getOrdinal() != ((Parameter) otherVar).getOrdinal()) {
			return false;
		}
		// If we have a VariableImpl or either function is using custom variable storage
		// then they are only equivalent if the storage is the same.
		Function otherFunction = otherVar.getFunction();
		boolean eitherHasCustomVariableStorage =
			(function == null || function.hasCustomVariableStorage()) ||
				(otherFunction == null || otherFunction.hasCustomVariableStorage());
		if (eitherHasCustomVariableStorage &&
			!SystemUtilities.isEqual(getVariableStorage(), otherVar.getVariableStorage())) {
			return false;
		}
		if (getFirstUseOffset() != otherVar.getFirstUseOffset()) {
			return false;
		}
		if (!DataTypeUtilities.isSameOrEquivalentDataType(getDataType(), otherVar.getDataType())) {
			return false;
		}
		return true;
	}

	/**
	 * Update variable storage and data-type associated with the underlying variable symbol.
	 * If function does not use custom storage, the specified storage will be ignored and set
	 * to UNASSIGNED.
	 * @param newStorage
	 * @param dt
	 */
	void setStorageAndDataType(VariableStorage newStorage, DataType dt) {
		if (this instanceof Parameter && !function.hasCustomVariableStorage()) {
			newStorage = VariableStorage.UNASSIGNED_STORAGE;
		}
		symbol.setStorageAndDataType(newStorage, dt);
		storage = newStorage;
	}

//	/**
//	 * Flush the current variable storage to the underlying symbol.  This method assumes
//	 * that the dynamically assigned storage was previously set via 
//	 * {@link #setDynamicStorage(VariableStorage)} when transitioning from
//	 * dynamic to custom.
//	 */
//	void flushVariableStorage() {
//		symbol.setStorageAndDataType(function.hasCustomVariableStorage() ? getVariableStorage()
//				: VariableStorage.UNASSIGNED_STORAGE, getDataType());
//	}

}
