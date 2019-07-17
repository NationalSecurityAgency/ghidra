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
package ghidra.feature.vt.api.stringable.deprecated;

import java.util.StringTokenizer;

import ghidra.feature.vt.api.util.Stringable;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.InvalidInputException;

public class ParameterInfo extends ParameterImpl {

	static ParameterInfo createParameterInfo(Parameter param) {
		try {
			ParameterInfo paramInfo =
				new ParameterInfo(param.getName(), param.getOrdinal(), param.getDataType(),
					param.getVariableStorage(), param.getProgram(), param.getSource());

			paramInfo.setComment(param.getComment());

			return paramInfo;
		}
		catch (InvalidInputException e) {
			throw new AssertException("Failed to clone parameter: " +
				param.getFunction().getName() + ":" + param.getName());
		}
	}

	static ParameterInfo createParameterInfo(String localVariableInfoString, Program program) {

		try {
			StringTokenizer tokenizer =
				new StringTokenizer(localVariableInfoString, Stringable.DELIMITER);
			tokenizer.nextToken(); // the first element is the class name

			long managerUniversalID = Long.parseLong(tokenizer.nextToken());
			long dataTypeID = Long.parseLong(tokenizer.nextToken());
			String dataTypeName = tokenizer.nextToken();

			DataType dt = getDataType(program, managerUniversalID, dataTypeID);
			if (dt == null || !dt.getName().equals(dataTypeName)) {
				throw new AssertException("Data type name/ID mismatch " + dt.getName() +
					" doesn't match " + dataTypeName + ".");
			}

			int ordinal = Integer.parseInt(tokenizer.nextToken());
			String localVariableName = tokenizer.nextToken();
			SourceType sourceType = SourceType.valueOf(tokenizer.nextToken());
			String comment = tokenizer.nextToken();

			VariableStorage storage = VariableStorage.deserialize(program, tokenizer.nextToken());

			ParameterInfo paramInfo =
				new ParameterInfo(localVariableName, ordinal, dt, storage, program, sourceType);
			paramInfo.setComment(comment);

			return paramInfo;
		}
		catch (Exception e) {
			throw new AssertException("Failed to deserialize local variable (" +
				localVariableInfoString + "): " + e.getMessage());
		}
	}

	private static DataType getDataType(Program program, long managerUniversalID, long dataTypeID) {
		DataTypeManager dataTypeManager = program.getDataTypeManager();
		long actualUniversalID = dataTypeManager.getUniversalID().getValue();
		if (actualUniversalID != managerUniversalID) {
			throw new AssertException("Provided data type manager ID of " + actualUniversalID +
				" doesn't matched saved ID of " + managerUniversalID + ".");
		}
		return dataTypeManager.getDataType(dataTypeID);
	}

	ParameterInfo(String name, int firstUseOffset, DataType dataType, VariableStorage storage,
			Program program, SourceType sourceType) throws InvalidInputException {
		super(name, firstUseOffset, dataType, storage, true, program, sourceType);
	}

	String convertToString() {

		DataTypeManager dataTypeMananger = getProgram().getDataTypeManager();
		DataType dt = getDataType();

		StringBuffer buffy = new StringBuffer();
		buffy.append(getClass().getSimpleName()).append(Stringable.DELIMITER);
		buffy.append(Long.toString(dataTypeMananger.getUniversalID().getValue())).append(
			Stringable.DELIMITER);
		buffy.append(Long.toString(dataTypeMananger.getID(dt))).append(Stringable.DELIMITER);
		buffy.append(dt.getName()).append(Stringable.DELIMITER);
		buffy.append(Integer.toString(getOrdinal())).append(Stringable.DELIMITER);
		buffy.append(getName()).append(Stringable.DELIMITER);
		buffy.append(getSource().name()).append(Stringable.DELIMITER);
		buffy.append(getComment()).append(Stringable.DELIMITER);
		buffy.append(getVariableStorage().getSerializationString());
		return buffy.toString();
	}

	public Parameter createParameterDefinition(Function destFunction, int ordinal) {
		try {
			Parameter var =
				new MyParameter(getName(), getOrdinal(), getDataType(),
					getVariableStorage().getSerializationString(), destFunction.getProgram(),
					getSource());
			var.setComment(getComment());
			return var;
		}
		catch (InvalidInputException e) {
			Msg.error(this, "Unable to apply parameter '" + getName() + "' to function " +
				destFunction.getName() + ": " + e.getMessage());
			return null;
		}
	}

	private static class MyParameter extends ParameterImpl {
		MyParameter(String name, int ordinal, DataType dataType, String serializedStorage,
				Program program, SourceType sourceType) throws InvalidInputException {
			super(name, ordinal, dataType, VariableStorage.deserialize(program, serializedStorage),
				true, program, sourceType);
		}
	}

}
