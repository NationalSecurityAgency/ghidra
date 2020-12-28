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
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;

/**
 * 
 */
class OldStackFrameDB implements StackFrame {

	private int localSize;      // if local size == 0, size is longest defined local
	private int paramStart;
	private int returnStart;
	private List<Variable> variables;

	private OldFunctionDataDB function;
	private OldFunctionManager functionManager;
	private OldStackVariableDBAdapter adapter;

	private final static Variable[] emptyArray = new Variable[0];

	/**
	 * Construct a function stack frame.
	 * @param function
	 * @param variables
	 */
	OldStackFrameDB(OldFunctionDataDB function) {
		this.function = function;
		functionManager = function.getFunctionManager();
		adapter = functionManager.getStackVariableAdapter();
		refresh();
	}

	void refresh() {
		this.paramStart = function.getStackParamOffset();
		this.returnStart = function.getStackReturnOffset();
		this.localSize = function.getStackLocalSize();
		variables = null;
		loadStackVariables();
	}

	OldFunctionManager getFunctionManager() {
		return functionManager;
	}

	OldFunctionDataDB getFunctionData() {
		return function;
	}

	/**
	 * Get the function that this stack belongs to.
	 * @return the function
	 */
	@Override
	public Function getFunction() {
		return null;
	}

	/**
	 * Load the stack variables for this frame.
	 */
	private void loadStackVariables() {
		if (variables != null)
			return;
		try {
			variables = new ArrayList<Variable>();
			Field[] keys = adapter.getStackVariableKeys(function.getKey());
			for (int i = 0; i < keys.length; i++) {
				DBRecord varRec = adapter.getStackVariableRecord(keys[i].getLongValue());
				variables.add(getStackVariable(varRec));
			}
			Collections.sort(variables, StackVariableComparator.get());
		}
		catch (IOException e) {
			functionManager.dbError(e);
		}
	}

	private Variable getStackVariable(DBRecord record) {

		int offset = record.getIntValue(OldStackVariableDBAdapter.STACK_VAR_OFFSET_COL);
		long dataTypeId = record.getLongValue(OldStackVariableDBAdapter.STACK_VAR_DATA_TYPE_ID_COL);
		//int dtLength = record.getIntValue(OldStackVariableDBAdapter.STACK_VAR_DT_LENGTH_COL);
		String name = record.getString(OldStackVariableDBAdapter.STACK_VAR_NAME_COL);
		String comment = record.getString(OldStackVariableDBAdapter.STACK_VAR_COMMENT_COL);

		DataType dataType = functionManager.getDataType(dataTypeId);

		Variable var;
		try {
			if (isParameterOffset(offset)) {
				var = new ParameterImpl(name, dataType, offset, functionManager.getProgram());
			}
			else {
				var = new LocalVariableImpl(name, dataType, offset, functionManager.getProgram());
			}
		}
		catch (InvalidInputException e) {
			throw new RuntimeException(e); // unexpected
		}
		catch (AddressOutOfBoundsException e) {
			Msg.error(this, "Invalid stack variable '" + name + "' in function at " +
				function.getEntryPoint() + ": " + e.getMessage());
			try {
				var = new LocalVariableImpl(name, 0, dataType, VariableStorage.BAD_STORAGE,
					functionManager.getProgram());
			}
			catch (InvalidInputException e1) {
				throw new RuntimeException(e); // unexpected
			}
		}
		if (comment != null && comment.length() != 0) {
			var.setComment(comment);
		}
		return var;
	}

	/**
	 * @see ghidra.program.model.listing.StackFrame#createVariable(java.lang.String, int, ghidra.program.model.data.DataType, ghidra.program.model.symbol.SourceType)
	 */
	@Override
	public Variable createVariable(String name, int offset, DataType dataType, SourceType source) {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.model.listing.StackFrame#getStackVariables()
	 */
	@Override
	public Variable[] getStackVariables() {
		synchronized (function) {
			loadStackVariables();
			if (variables.isEmpty()) {
				return emptyArray;
			}
			return variables.toArray(emptyArray);
		}
	}

	/**
	 * Get all defined local variables.
	 *
	 * @return an array of all local variables
	 */
	@Override
	public Variable[] getLocals() {
		synchronized (function) {
			loadStackVariables();
			if (paramStart >= 0) {
				return getNegativeVariables();
			}
			return getPositiveVariables();
		}
	}

	/**
	 * Get all defined parameters.
	 *
	 * @return an array of parameters.
	 */
	@Override
	public Variable[] getParameters() {
		synchronized (function) {
			loadStackVariables();
			return (paramStart >= 0) ? getPositiveVariables() : getNegativeVariables();
		}
	}

	/**
	 * Get the size of this stack frame in bytes.
	 *
	 * @return stack frame size
	 */
	@Override
	public int getFrameSize() {
		synchronized (function) {
			int size = getLocalSize();
			size += (growsNegative() ? getPositiveSize() : getNegativeSize());

			return size;
		}
	}

	/**
	 * Get the local portion of the stack frame in bytes.
	 *
	 * @return local frame size
	 */
	@Override
	public int getLocalSize() {
		synchronized (function) {
			if (localSize > 0) {
				return localSize;
			}

			if (growsNegative()) {
				return getNegativeSize();
			}
			return getPositiveSize();
		}
	}

	/**
	 * A stack that grows negative has local references negative and
	 * parameter references positive.  A positive growing stack has
	 * positive locals and negative parameters.
	 *
	 * @return true if the stack grows in a negative direction.
	 */
	@Override
	public boolean growsNegative() {
		synchronized (function) {
			return (paramStart >= 0);
		}
	}

	/**
	 * Set the size of the local stack in bytes.
	 *
	 * @param size size of local stack
	 */
	@Override
	public void setLocalSize(int size) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Get the parameter portion of the stack frame in bytes.
	 *
	 * @return parameter frame size
	 */
	@Override
	public int getParameterSize() {
		synchronized (function) {
			if (growsNegative()) {
				return getPositiveSize() - getParameterOffset();
			}
			return getNegativeSize() + getParameterOffset();
		}
	}

	/**
	 * @return the number of parameters on the stack
	 */
	int getParameterCount() {
		synchronized (function) {
			loadStackVariables();
			if (growsNegative()) {
				return getPositiveCount();
			}
			return getNegativeCount();
		}
	}

	/**
	 * Clear the stack variable defined at offset
	 *
	 * @param offset Offset onto the stack to be cleared.
	 */
	@Override
	public void clearVariable(int offset) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Get the offset to the start of the parameters.
	 *
	 * @return offset
	 */
	@Override
	public int getParameterOffset() {
		synchronized (function) {
			// if paramStart hasn't been specified, try to find the first parameter
			if (paramStart == 0 && !variables.isEmpty()) {

				// find the first stack variable defined at or after 0
				loadStackVariables();
				Object key = new Integer(0);
				int loc = Collections.binarySearch(variables, key, StackVariableComparator.get());
				loc = (loc < 0 ? -1 - loc : loc);
				if (loc < variables.size()) {
					Variable var = variables.get(loc);
					if (var != null) {
						return var.getStackOffset();
					}
				}
			}
			return paramStart;
		}
	}

	/**
	 * Get the stack variable containing offset.  This may fall in
	 * the middle of a defined variable.
	 *
	 * @param offset offset of on stack to get variable.
	 */
	@Override
	public int getReturnAddressOffset() {
		synchronized (function) {
			return returnStart;
		}
	}

	/**
	 * Set the return address stack size.
	 * @param offset offset of return address.
	 */
	@Override
	public void setReturnAddressOffset(int offset) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Get the stack variable containing offset.  This may fall in
	 * the middle of a defined variable.
	 *
	 * @param offset offset of on stack to get variable.
	 */
	@Override
	public Variable getVariableContaining(int offset) {
		synchronized (function) {
			loadStackVariables();
			Object key = new Integer(offset);
			int index = Collections.binarySearch(variables, key, StackVariableComparator.get());
			if (index >= 0) {
				return variables.get(index);
			}
			index = -index - 1;
			index = index - 1;
			if (index < 0) {
				return null;
			}
			Variable var = variables.get(index);
			int stackOffset = var.getStackOffset();
			if ((stackOffset + var.getLength()) > offset) {
				return var;
			}
			return null;
		}
	}

	/**
	 * Get the size of the negative portion of the stack
	 *
	 * @return the negative portion size
	 */
	private int getNegativeSize() {
		if (variables.isEmpty()) {
			return (growsNegative() ? 0 : -paramStart);
		}

		Variable var = variables.get(0);
		int stackOffset = var.getStackOffset();
		if (stackOffset >= 0) {
			return (growsNegative() ? 0 : -paramStart);
		}
		return 0 - stackOffset;
	}

	/**
	 * Get the size of the positive portion of the stack (including 0)
	 *
	 * @return the positive portion size
	 */
	private int getPositiveSize() {
		if (variables.isEmpty()) {
			return (growsNegative() ? paramStart : 0);
		}
		Variable var = variables.get(variables.size() - 1);
		int stackOffset = var.getStackOffset();
		if (stackOffset < 0) {
			return (growsNegative() ? paramStart : 0);
		}
		return stackOffset + var.getLength();
	}

	/**
	 * Get all the stack variables in the negative portion of the stack.
	 * This EXCLUDES any variables defined before the parameter offset if the
	 * parameter offset is negative.
	 *
	 * @return an array of variables defined on the negative portion of the frame.
	 */
	private Variable[] getNegativeVariables() {
		if (variables.isEmpty()) {
			return emptyArray;
		}
		int length = variables.size();
		// find the end of the negatives
		int index = 0;
		for (index = 0; index < length; index++) {
			Variable var = variables.get(index);
			int stackOffset = var.getStackOffset();
			int start = stackOffset;
			if (start >= 0 || start > paramStart) {
				break;
			}
		}
		if (index == 0) {
			return emptyArray;
		}

		// return the variables in the order of -1 to -n
		List<Variable> vars = variables.subList(0, index);
		int size = vars.size();
		Variable[] retvars = new Variable[size];
		int pos = size - 1;
		for (int i = 0; i < size; i++, pos--) {
			retvars[pos] = vars.get(i);
		}
		return retvars;
	}

	/**
	 * Get all the stack variables in the postive portion of the stack.
	 * This EXCLUDES any variables defined before the parameter offset if the
	 * parameter offset is positive.
	 *
	 * @return an array of variables defined on the positive portion of the frame.
	 */
	private Variable[] getPositiveVariables() {
		if (variables.isEmpty()) {
			return emptyArray;
		}
		int length = variables.size();
		// find the end of the negatives
		int index = 0;
		for (index = 0; index < length; index++) {
			Variable var = variables.get(index);
			int stackOffset = var.getStackOffset();
			if (stackOffset >= 0 && stackOffset >= paramStart) {
				break;
			}
		}
		if (index == length) {
			return emptyArray;
		}
		List<Variable> vars = variables.subList(index, length);
		return vars.toArray(emptyArray);
	}

	/**
	 * Get a count of all the stack variables in the negative portion of the frame.
	 * This EXCLUDES any variables defined before the parameter offset if the
	 * parameter offset is negative.
	 */
	private int getNegativeCount() {
		if (variables.isEmpty()) {
			return 0;
		}
		int length = variables.size();
		// find the end of the negatives
		int index = 0;
		for (index = 0; index < length; index++) {
			Variable var = variables.get(index);
			int stackOffset = var.getStackOffset();
			if (stackOffset >= 0 || stackOffset >= paramStart) {
				break;
			}
		}
		if (index == 0) {
			return 0;
		}
		return index;
	}

	/**
	 * Get all the stack variables in the postive portion of the stack.
	 * This EXCLUDES any variables defined before the parameter offset if the
	 * parameter offset is positive.
	 *
	 * @return an array of variables defined on the positive portion of the frame.
	 */
	private int getPositiveCount() {
		if (variables.isEmpty()) {
			return 0;
		}
		int length = variables.size();
		// find the end of the negatives
		int index = 0;
		for (index = 0; index < length; index++) {
			Variable var = variables.get(index);
			int stackOffset = var.getStackOffset();
			if (stackOffset >= 0 && stackOffset >= paramStart) {
				break;
			}
		}
		if (index == length) {
			return 0;
		}
		return length - index;
	}

	/**
	 * @param offset
	 * @return boolean
	 */
	@Override
	public boolean isParameterOffset(int offset) {
		return offset >= 0 ? growsNegative() : !growsNegative();
	}

	/**
	 * Returns whether some other stack frame is "equivalent to" this one.
	 * The stack frame is considered equal to another even if they are each
	 * part of a different function.
	 */
	@Override
	public boolean equals(Object obj) {
		synchronized (function) {
			if (obj == null) {
				return false;
			}
			if (obj == this) {
				return true;
			}
			if (!(obj instanceof OldStackFrameDB)) {
				return false;
			}
			OldStackFrameDB otherFrame = (OldStackFrameDB) obj;
			if ((this.getLocalSize() != otherFrame.getLocalSize()) ||
				(this.getParameterOffset() != otherFrame.getParameterOffset()) ||
				(this.returnStart != otherFrame.returnStart) ||
				(this.variables.size() != otherFrame.variables.size())) {
				return false;
			}
			Iterator<Variable> myIter = this.variables.iterator();
			Iterator<Variable> otherIter = otherFrame.variables.iterator();
			while (myIter.hasNext() && otherIter.hasNext()) {
				Variable myVar = myIter.next();
				Variable otherVar = otherIter.next();
				if (!(myVar.equals(otherVar))) {
					return false;
				}
			}
			return true;
		}
	}

}
