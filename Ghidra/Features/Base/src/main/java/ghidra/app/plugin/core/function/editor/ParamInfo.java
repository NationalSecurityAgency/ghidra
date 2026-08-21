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
package ghidra.app.plugin.core.function.editor;

import java.util.Objects;

import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.InvalidInputException;

public class ParamInfo implements Comparable<ParamInfo> {

	private String name;
	private DataType formalDataType;
	private VariableStorage storage;
	private boolean isCustomStorage;
	private int ordinal;

	private boolean hasStorageConflict = false;

	private FunctionDataView functionData;
	private Program program;

	ParamInfo(FunctionDataView functionData, Parameter parameter) {
		this(functionData, parameter.getName(), parameter.getFormalDataType(),
			parameter.getVariableStorage(), functionData.canCustomizeStorage(),
			parameter.getOrdinal());
	}

	ParamInfo(FunctionDataView functionData, ParameterDefinition paramDefinition) {
		this(functionData, paramDefinition.getName(), paramDefinition.getDataType(),
			VariableStorage.UNASSIGNED_STORAGE, false, paramDefinition.getOrdinal());
		this.functionData = functionData;
	}

	ParamInfo(FunctionDataView functionData, String name, DataType formalDataType,
			VariableStorage storage, boolean isCustomStorage, int ordinal) {
		this.functionData = functionData;
		this.program = functionData.getProgram();
		this.name = SymbolUtilities.isDefaultParameterName(name) ? null : name;
		this.formalDataType = formalDataType;
		this.storage = storage;
		this.isCustomStorage = isCustomStorage;
		this.ordinal = ordinal;
	}

	ParamInfo copy() {
		return new ParamInfo(functionData, name, formalDataType, storage, isCustomStorage, ordinal);
	}

	public boolean isSame(ParamInfo otherParam) {
		if (!Objects.equals(name, otherParam.name) ||
			isAutoParameter() != otherParam.isAutoParameter() ||
			!formalDataType.equals(otherParam.getFormalDataType())) {
			return false;
		}
		return !isCustomStorage || storage.equals(otherParam.storage);
	}

	@Override
	public int compareTo(ParamInfo o) {
		int c = ordinal - o.ordinal;
		if (c != 0) {
			return c;
		}
		return getName().compareTo(o.getName());
	}

	@Override
	public final boolean equals(Object obj) {
		return this == obj;
	}

	@Override
	public final int hashCode() {
		return super.hashCode();
	}

	public String getName(boolean returnNullForDefault) {
		if (returnNullForDefault) {
			return name;
		}
		return getName();
	}

	public String getName() {
		return name != null ? name
				: SymbolUtilities.getDefaultParamName(ordinal - functionData.getAutoParamCount());
	}

	DataType getDataType() {
		DataType dt = formalDataType;
		if (storage.isForcedIndirect()) {
			DataTypeManager dtm = program.getDataTypeManager();
			int ptrSize = storage.size();
			if (ptrSize != dtm.getDataOrganization().getPointerSize()) {
				dt = dtm.getPointer(dt, ptrSize);
			}
			else {
				dt = dtm.getPointer(dt);
			}
		}
		return dt;
	}

	public DataType getFormalDataType() {
		return formalDataType;
	}

	public VariableStorage getStorage() {
		return storage;
	}

	boolean isAutoParameter() {
		return storage.isAutoStorage();
	}

	boolean isReturnParameter() {
		return ordinal == Parameter.RETURN_ORIDINAL;
	}

	boolean isForcedIndirect() {
		return storage.isForcedIndirect();
	}

	@Override
	public String toString() {
		return getName() + "@" + getStorage();
	}

	int getOrdinal() {
		return ordinal;
	}

	void setOrdinal(int i) {
		this.ordinal = i;
	}

	void setName(String name) {
		if (name != null && (name.length() == 0 || SymbolUtilities.isDefaultParameterName(name))) {
			name = null;
		}
		this.name = name;
	}

	void setFormalDataType(DataType formalDataType) {
		this.formalDataType = formalDataType;
	}

	void setStorage(VariableStorage storage) {
		this.isCustomStorage = functionData.canCustomizeStorage();
		this.storage = storage;
	}

	Parameter getParameter(SourceType source) {

		VariableStorage variableStorage =
			isCustomStorage ? storage : VariableStorage.UNASSIGNED_STORAGE;
		try {
			if (ordinal == Parameter.RETURN_ORIDINAL) {
				return new ReturnParameterImpl(formalDataType, variableStorage, true, program);
			}
			String n = name;
			if (n == null) {
				source = SourceType.DEFAULT;
				n = SymbolUtilities.getDefaultParamName(ordinal);
			}
			return new ParameterImpl(n, ordinal, formalDataType, variableStorage, true, program,
				source);
		}
		catch (InvalidInputException e) {
			throw new AssertException("Unexpected exception", e);
		}
	}

	boolean hasStorageConflict() {
		return hasStorageConflict;
	}

	void setHasStorageConflict(boolean state) {
		hasStorageConflict = state;
	}
}
