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
package ghidra.program.database.oldfunction;

import java.io.IOException;
import java.util.*;

import db.Field;
import db.DBRecord;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.StringUtilities;
import ghidra.util.exception.InvalidInputException;

/**
 *
 */
class OldFunctionDataDB {

	private AddressMap addrMap;
	private OldFunctionManager functionManager;
	private ProgramDB program;
	private OldFunctionDBAdapter functionAdapter;
	private OldRegisterVariableDBAdapter registerAdapter;

	private DBRecord functionRecord;
	private Address entryPoint;

	private AddressSetView body;
	private OldStackFrameDB frame;
	private List<Parameter> regParams;

	OldFunctionDataDB(OldFunctionManager functionManager, AddressMap addrMap, DBRecord functionRecord,
			AddressSetView body) {

		this.functionManager = functionManager;
		this.addrMap = addrMap;
		this.functionRecord = functionRecord;
		this.body = body;

		entryPoint = addrMap.decodeAddress(functionRecord.getKey());
		program = functionManager.getProgram();
		functionAdapter = functionManager.getFunctionAdapter();
		registerAdapter = functionManager.getRegisterVariableAdapter();
		frame = new OldStackFrameDB(this);

	}

	AddressMap getAddressMap() {
		return addrMap;
	}

	OldFunctionManager getFunctionManager() {
		return functionManager;
	}

	/**
	 * @see ghidra.program.model.listing.Function#getProgram()
	 */
	public Program getProgram() {
		return program;
	}

	/**
	 * @see ghidra.program.model.listing.Function#getComment()
	 */
	public synchronized String getComment() {
		CodeUnit cu = program.getCodeManager().getCodeUnitContaining(entryPoint);

		return cu.getComment(CodeUnit.PLATE_COMMENT);
	}

	/**
	 * @see ghidra.program.model.listing.Function#getCommentAsArray()
	 */
	public synchronized String[] getCommentAsArray() {
		return StringUtilities.toLines(getComment());
	}

	/**
	 * @see ghidra.program.model.listing.Function#getRepeatableComment()
	 */
	public String getRepeatableComment() {
		String comment = functionRecord.getString(OldFunctionDBAdapter.REPEATABLE_COMMENT_COL);
		return comment;
	}

	/**
	 * @see ghidra.program.model.listing.Function#getRepeatableCommentAsArray()
	 */
	public String[] getRepeatableCommentAsArray() {
		String comment = getRepeatableComment();
		return StringUtilities.toLines(comment);
	}

	/**
	 * @see ghidra.program.model.listing.Function#getEntryPoint()
	 */
	public synchronized Address getEntryPoint() {
		return entryPoint;
	}

	/**
	 * @see ghidra.program.model.listing.Function#getBody()
	 */
	public AddressSetView getBody() {
		if (body == null) {
			body = functionManager.getFunctionBody(functionRecord.getKey());
		}
		return body;
	}

	/**
	 * @see ghidra.program.model.listing.Function#getReturnType()
	 */
	public synchronized DataType getReturnType() {
		long typeId = functionRecord.getLongValue(OldFunctionDBAdapter.RETURN_DATA_TYPE_ID_COL);
		DataType dt = functionManager.getDataType(typeId);
		if (dt == null) {
			dt = DataType.DEFAULT;
		}
		return dt;
	}

	/**
	 * @see ghidra.program.model.listing.Function#getStackFrame()
	 */
	public StackFrame getStackFrame() {
		return frame;
	}

	/**
	 * @see ghidra.program.model.listing.Function#getStackPurgeSize()
	 */
	public int getStackDepthChange() {
		int value = functionRecord.getIntValue(OldFunctionDBAdapter.STACK_DEPTH_COL);
		return value;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.listing.Function#isStackDepthValid()
	 */
	public boolean isStackDepthValid() {
		if (getStackDepthChange() > 0xffffff) {
			return false;
		}
		return true;
	}

	/**
	 * Get the first parameter offset for the function stack frame.
	 * @return int
	 */
	int getStackParamOffset() {
		return functionRecord.getIntValue(OldFunctionDBAdapter.STACK_PARAM_OFFSET_COL);
	}

	/**
	 * Get the return value offset for the function stack frame.
	 * @return int
	 */
	int getStackReturnOffset() {
		return functionRecord.getIntValue(OldFunctionDBAdapter.STACK_RETURN_OFFSET_COL);
	}

	/**
	 * Get the stack space used by this function.
	 * @return int
	 */
	int getStackLocalSize() {
		return functionRecord.getIntValue(OldFunctionDBAdapter.STACK_LOCAL_SIZE_COL);
	}

	/**
	 * Load the register variable/parameter list from the database.
	 * @return register
	 */
	private synchronized void loadRegisterParameterList() {
		if (regParams != null)
			return;
		regParams = new ArrayList<Parameter>();
		try {
			Field[] keys = registerAdapter.getRegisterVariableKeys(functionRecord.getKey());
			for (int i = 0; i < keys.length; i++) {
				DBRecord varRec = registerAdapter.getRegisterVariableRecord(keys[i].getLongValue());
				regParams.add(getRegisterParameter(varRec, i));
			}
// TODO Does register variable list need to be sorted?
		}
		catch (IOException e) {
			functionManager.dbError(e);
		}
	}

	private Parameter getRegisterParameter(DBRecord record, int ordinal) {
		String name = record.getString(OldRegisterVariableDBAdapter.REG_VAR_NAME_COL);
		long dataTypeId =
			record.getLongValue(OldRegisterVariableDBAdapter.REG_VAR_DATA_TYPE_ID_COL);
		String regName = record.getString(OldRegisterVariableDBAdapter.REG_VAR_REGNAME_COL);

		DataType dataType = functionManager.getDataType(dataTypeId);

		try {
			VariableStorage storage = VariableStorage.BAD_STORAGE;
			Register register =
				functionManager.getProgram().getProgramContext().getRegister(regName);
			if (register == null) {
				Msg.error(this, "Invalid parameter, register not found: " + regName);
			}
			else {
				storage = new VariableStorage(program, register.getAddress(), dataType.getLength());
			}
			return new OldFunctionParameter(name, ordinal, dataType, storage, program,
				SourceType.USER_DEFINED);
		}
		catch (InvalidInputException e) {
			Msg.error(this,
				"Invalid parameter '" + name + "' in function at " + entryPoint.toString());
			try {
				return new OldFunctionParameter(name, ordinal, dataType,
					VariableStorage.BAD_STORAGE, program, SourceType.USER_DEFINED);
			}
			catch (InvalidInputException e1) {
				// should not occur
				throw new RuntimeException(e1);
			}
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.listing.Function#getParameters()
	 */
	public synchronized Parameter[] getParameters() {

		loadRegisterParameterList();

		Parameter[] parms = new Parameter[regParams.size() + frame.getParameterCount()];
		int ordinal = 0;

		Iterator<Parameter> iter = regParams.iterator();
		while (iter.hasNext()) {
			Parameter rp = iter.next();
			parms[ordinal++] = rp;
		}

		try {
			Variable[] stackParams = frame.getParameters();
			for (int i = 0; i < stackParams.length; i++) {
				parms[ordinal++] = new OldFunctionParameter(stackParams[i].getName(), ordinal,
					stackParams[i].getDataType(), stackParams[i].getVariableStorage(), program,
					SourceType.USER_DEFINED);
			}
		}
		catch (InvalidInputException e) {
			throw new RuntimeException(e); // unexpected
		}
		return parms;
	}

	public long getKey() {
		return functionRecord.getKey();
	}

}

class OldFunctionParameter extends ParameterImpl {

	protected OldFunctionParameter(String name, int ordinal, DataType dataType,
			VariableStorage storage, Program program, SourceType sourceType)
			throws InvalidInputException {
		super(name, ordinal, dataType, storage, true, program, sourceType);
	}

}
