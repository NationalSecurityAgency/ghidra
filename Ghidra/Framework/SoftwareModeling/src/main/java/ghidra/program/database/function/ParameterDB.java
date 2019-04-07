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

import ghidra.program.database.symbol.SymbolDB;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.*;

class ParameterDB extends VariableDB implements Parameter {

	/**
	 * @param function
	 * @param s
	 */
	ParameterDB(FunctionDB function, SymbolDB s) {
		super(function, s);
	}

	@Override
	public int getFirstUseOffset() {
		return 0;
	}

	@Override
	public int getOrdinal() {
		int baseOrdinal = function.getAutoParamCount();
		int ordinal = symbol.getOrdinal();
		return baseOrdinal + ordinal;
	}

	void setOrdinal(int ordinal) {
		if (getOrdinal() == ordinal) {
			return;
		}
		int baseOrdinal = function.getAutoParamCount();
		symbol.setOrdinal(ordinal - baseOrdinal);
	}

	@Override
	void setDynamicStorage(VariableStorage storage) {
		this.storage = storage;
	}

	@Override
	public DataType getDataType() {
		DataType dt = getFormalDataType();
		VariableStorage varStorage = getVariableStorage();
		if (varStorage.isForcedIndirect()) {
			Program program = function.getProgram();
			DataTypeManager dtm = program.getDataTypeManager();
			int ptrSize = varStorage.size();
			if (ptrSize != dtm.getDataOrganization().getPointerSize()) {
				dt = dtm.getPointer(dt, ptrSize);
			}
			else {
				dt = dtm.getPointer(dt);
			}
		}
		return dt;
	}

	@Override
	public DataType getFormalDataType() {
		return super.getDataType();
	}

	@Override
	public boolean isForcedIndirect() {
		VariableStorage varStorage = getVariableStorage();
		return varStorage != null ? varStorage.isForcedIndirect() : false;
	}

	@Override
	public boolean isAutoParameter() {
		return false;
	}

	@Override
	public AutoParameterType getAutoParameterType() {
		return null;
	}

}
