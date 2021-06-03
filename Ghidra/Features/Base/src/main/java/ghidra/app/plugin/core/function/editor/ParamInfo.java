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

import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.InvalidInputException;

public class ParamInfo {

	private Parameter original;
	private String name;
	private DataType formalDataType;
	private VariableStorage storage;
	private int ordinal;
	private FunctionEditorModel model;

	ParamInfo(FunctionEditorModel model, Parameter parameter) {
		this(model, parameter.getName(), parameter.getFormalDataType(),
			parameter.getVariableStorage(), parameter.getOrdinal());
		original = parameter;
	}

	ParamInfo(FunctionEditorModel model, ParameterDefinition paramDefinition) {
		this(model, paramDefinition.getName(), paramDefinition.getDataType(),
			VariableStorage.UNASSIGNED_STORAGE, paramDefinition.getOrdinal());
	}

	ParamInfo(FunctionEditorModel model, String name, DataType formalDataType,
			VariableStorage storage,
			int ordinal) {
		this.model = model;
		this.name = SymbolUtilities.isDefaultParameterName(name) ? null : name;
		this.formalDataType = formalDataType;
		this.storage = storage;
		this.ordinal = ordinal;
	}

	@Override
	public boolean equals(Object obj) {
		return this == obj;
	}

	@Override
	public int hashCode() {
		return getName().hashCode();
	}

	public String getName() {
		return name != null ? name : SymbolUtilities.getDefaultParamName(ordinal -
			model.getAutoParamCount());
	}

	DataType getDataType() {
		DataType dt = formalDataType;
		if (storage.isForcedIndirect()) {
			Program program = model.getProgram();
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
		if (original != null && original.getOrdinal() != i) {
			original = null;
		}
		this.ordinal = i;
	}

	void setName(String name) {
		if (name != null && name.length() == 0) {
			name = null;
		}
		this.name = name;
	}

	void setFormalDataType(DataType formalDataType) {
		this.formalDataType = formalDataType;
		original = null;
	}

	void setStorage(VariableStorage storage) {
		this.storage = storage;
		if (model.canCustomizeStorage()) {
			original = null;
		}
	}

	boolean isModified() {
		return original == null;
	}

	boolean isNameModified() {
		return original != null && !SystemUtilities.isEqual(original.getName(), getName());
	}

	/**
	 * @return unchanged original parameter or null if new or datatype was changed
	 */
	Parameter getOriginalParameter() {
		return original;
	}

	Parameter getParameter(boolean isCustom) {
		if (original != null) {
			return original;
		}

		VariableStorage variableStorage = isCustom ? storage : VariableStorage.UNASSIGNED_STORAGE;
		try {
			if (ordinal == Parameter.RETURN_ORIDINAL) {
				return new ReturnParameterImpl(formalDataType, variableStorage, true,
					model.getProgram());
			}
			// preserve original source type if name unchanged
			SourceType source = SourceType.USER_DEFINED;
			if (original != null && original.getName().equals(name)) {
				source = original.getSource();
			}
			return new MyParameter(name, formalDataType, variableStorage, model.getProgram(),
				source);
		}
		catch (InvalidInputException e) {
			throw new AssertException("Unexpected exception", e);
		}
	}

	private static class MyParameter extends ParameterImpl {

		MyParameter(String name, DataType dataType, VariableStorage storage, Program program,
				SourceType source) throws InvalidInputException {
			super(name, UNASSIGNED_ORDINAL, dataType, storage, true, program,
				SourceType.USER_DEFINED);
		}
	}

}
