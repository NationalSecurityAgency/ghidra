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

import ghidra.feature.vt.api.util.Stringable;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.InvalidInputException;

import java.util.StringTokenizer;

public class LocalVariableInfo extends LocalVariableImpl {

	static LocalVariableInfo createLocalVariableInfo(Variable localVariable) {
		try {
			LocalVariableInfo localVarInfo =
				new LocalVariableInfo(localVariable.getName(), localVariable.getFirstUseOffset(),
					localVariable.getDataType(), localVariable.getVariableStorage(),
					localVariable.getProgram(), localVariable.getSource());

			localVarInfo.setComment(localVariable.getComment());

			return localVarInfo;
		}
		catch (InvalidInputException e) {
			throw new AssertException("Failed to clone local variable: " +
				localVariable.getFunction().getName() + ":" + localVariable.getName());
		}
	}

	static LocalVariableInfo createLocalVariableInfo(String localVariableInfoString, Program program) {

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

			int firstUseOffset = Integer.parseInt(tokenizer.nextToken());
			String localVariableName = tokenizer.nextToken();
			SourceType sourceType = SourceType.valueOf(tokenizer.nextToken());
			String comment = tokenizer.nextToken();

			VariableStorage storage = VariableStorage.deserialize(program, tokenizer.nextToken());

			LocalVariableInfo localVarInfo =
				new LocalVariableInfo(localVariableName, firstUseOffset, dt, storage, program,
					sourceType);
			localVarInfo.setComment(comment);

			return localVarInfo;
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

	LocalVariableInfo(String name, int firstUseOffset, DataType dataType, VariableStorage storage,
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
		buffy.append(Integer.toString(getFirstUseOffset())).append(Stringable.DELIMITER);
		buffy.append(getName()).append(Stringable.DELIMITER);
		buffy.append(getSource().name()).append(Stringable.DELIMITER);
		buffy.append(getComment()).append(Stringable.DELIMITER);
		buffy.append(getVariableStorage().getSerializationString());
		return buffy.toString();
	}

	public Variable createLocalVariable(Function destFunction, Address destinationStorageAddress) {
		try {
			long offset = destinationStorageAddress.subtract(destFunction.getEntryPoint());
			Variable var =
				new MyLocalVariable(getName(), (int) offset, getDataType(),
					getVariableStorage().getSerializationString(), destFunction.getProgram(),
					getSource());
			var.setComment(getComment());
			return var;
		}
		catch (InvalidInputException e) {
			Msg.error(this, "Unable to apply local variable '" + getName() + "' to function " +
				destFunction.getName() + ": " + e.getMessage());
			return null;
		}
	}

	private static class MyLocalVariable extends LocalVariableImpl {
		MyLocalVariable(String name, int firstUseOffset, DataType dataType,
				String serializedStorage, Program program, SourceType sourceType)
				throws InvalidInputException {
			super(name, firstUseOffset, dataType, VariableStorage.deserialize(program,
				serializedStorage), true, program, sourceType);
		}
	}

}
