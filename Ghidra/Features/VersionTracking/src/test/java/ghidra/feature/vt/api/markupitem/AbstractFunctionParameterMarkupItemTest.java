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
package ghidra.feature.vt.api.markupitem;

import ghidra.feature.vt.db.VTTestUtils;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.data.DataTypeManagerDB;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;

public abstract class AbstractFunctionParameterMarkupItemTest extends AbstractVTMarkupItemTest {

	public AbstractFunctionParameterMarkupItemTest() {
		super();
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	protected DataType createByteDataType(ProgramDB program) {
		DataTypeManagerDB dataTypeManager = program.getDataTypeManager();
		DataType dataType = new ByteDataType(dataTypeManager);
		return dataTypeManager.addDataType(dataType, DataTypeConflictHandler.DEFAULT_HANDLER);
	}

	protected DataType createIntDataType(ProgramDB program) {
		int transaction = -1;
		try {
			transaction = program.startTransaction("Test - Create Data Type");
			DataTypeManagerDB dataTypeManager = program.getDataTypeManager();
			DataType dataType = new IntegerDataType(dataTypeManager);
			return dataTypeManager.addDataType(dataType, DataTypeConflictHandler.DEFAULT_HANDLER);
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

	protected Parameter addRegisterParameter(Function function, DataType dataType) throws Exception {
		Program program = function.getProgram();
		int transaction = -1;
		try {
			transaction = program.startTransaction("Test - Add Parameter");

			Register register = program.getProgramContext().getRegister("EAX");
			ParameterImpl parameter =
				new ParameterImpl(VTTestUtils.getRandomString(), dataType, register, program);
			return function.addParameter(parameter, SourceType.USER_DEFINED);
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

	protected Parameter addMemoryParameter(Function function, DataType dataType) throws Exception {
		Program program = function.getProgram();
		int transaction = -1;
		try {
			transaction = program.startTransaction("Test - Add Parameter");

			ParameterImpl parameter =
				new ParameterImpl(VTTestUtils.getRandomString(), dataType,
					function.getEntryPoint(), program);
			return function.addParameter(parameter, SourceType.USER_DEFINED);
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

	protected Parameter addStackParameter(Function function, DataType dataType) throws Exception {
		Program program = function.getProgram();
		int transaction = -1;
		try {
			transaction = program.startTransaction("Test - Add Parameter");
			int parameterCount = function.getParameterCount();
			int stackOffset = function.getStackFrame().getParameterOffset();
			if (parameterCount != 0) {
				Parameter[] parameters = function.getParameters();
				for (Parameter parameter : parameters) {
					DataType paramDataType = parameter.getDataType();
					stackOffset += paramDataType.getLength();
				}
			}
			Parameter parameter =
				new ParameterImpl(VTTestUtils.getRandomString(), dataType, stackOffset, program);
			return function.addParameter(parameter, SourceType.USER_DEFINED);
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

	protected void removeParameters(Function function) {
		Parameter[] parameters = function.getParameters();

		Program program = function.getProgram();
		int transaction = -1;
		try {
			transaction = program.startTransaction("Test - Remove Parameters");
			for (Parameter parameter : parameters) {
				function.removeParameter(parameter.getOrdinal());
			}
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}
}
