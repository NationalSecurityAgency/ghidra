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
/*
 * StackFrameImpl.java
 *
 * Created on January 18, 2002, 2:35 PM
 */

package ghidra.util;

import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;

import java.util.*;

import java.lang.UnsupportedOperationException;

/**
 * <p>Implements a simple stack frame for a function.  Each frame consists of a
 * local sections, parameter section, and save information (return address,
 * saved registers).
 *</p>
 * <p> When a frame is created, the parameter stack start offset must be set up.
 * If the parameter start is &gt;= 0, then the stack grows in the negative
 * direction. If the parameter start &lt; 0, then the stack grows in the positive
 * direction. When a frame is created the parameter start offset must be
 * specified. Later the parameter start offset can be changed, but it must
 * remain positive/negative if the frame was created with a positive/negative
 * value.
 * </p>
 * <p>WARNING! This implementation is deficient and is only used by the UndefinedFunction
 * implementation
 */

class StackFrameImpl implements StackFrame {

	protected final static Variable[] emptyArray = new Variable[0];

	protected int localSize = 0; // if local size == 0, size is longest defined local
	protected int returnStart = 0;
	protected List<Variable> variables = new ArrayList<Variable>();

	private final Function function;
	private final int paramStart;
	private final boolean growsNegative;

	/**
	 * Creates a new Stack Frame.
	 * Stack characteristics are established at time of construction 
	 * (e.g., parameter offset, negative-growth, etc.).
	 */
	StackFrameImpl(Function function) {
		this.function = function;
		growsNegative = function.getProgram().getCompilerSpec().stackGrowsNegative();
		Integer baseOffset = VariableUtilities.getBaseStackParamOffset(function);
		paramStart = baseOffset != null ? (int) baseOffset.longValue() : UNKNOWN_PARAM_OFFSET;
	}

	/**
	 * A variable owned by this stack changed, notify someone.
	 *
	 * @param stackVar the variable that changed.
	 */
	void variableChanged(LocalVariableImpl stackVar) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Create a new stack variable.  
	 * 
	 * Specified source is always ignored
	 * and the variable instance returned will never be a parameter.
	 * @see ghidra.program.model.listing.StackFrame#createVariable(String, int, DataType, SourceType)
	 */
	@Override
	public Variable createVariable(String name, int offset, DataType dataType,
			final SourceType source) throws InvalidInputException {

		throw new UnsupportedOperationException();
	}

	@Override
	public Variable[] getStackVariables() {
		return getAllVariables();
	}

	@Override
	public Variable[] getLocals() {
		if (getParameterOffset() >= 0) {
			return getNegativeVariables();
		}
		return getPositiveVariables();
	}

	@Override
	public Variable[] getParameters() {

		return (getParameterOffset() >= 0) ? getPositiveVariables() : getNegativeVariables();
	}

	@Override
	public int getFrameSize() {
		int size = getLocalSize();
		size += (growsNegative() ? getPositiveSize() : getNegativeSize());

		return size;
	}

	@Override
	public int getLocalSize() {
		if (localSize > 0) {
			return localSize;
		}

		if (growsNegative()) {
			return getNegativeSize();
		}
		return getPositiveSize();
	}

	@Override
	public boolean growsNegative() {
		return growsNegative;
	}

	@Override
	public void setLocalSize(int size) {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getParameterSize() {
		if (growsNegative()) {
			return getPositiveSize() - getParameterOffset();
		}
		return getNegativeSize() + getParameterOffset();
	}

	/**
	 * Gets the number of parameters in the stack frame regardless
	 * of the direction the stack grows in.
	 * 
	 * @return the number of parameters in the stack frame.
	 */
	public int getParameterCount() {
		if (growsNegative()) {
			return getPositiveCount();
		}
		return getNegativeCount();
	}

	@Override
	public void clearVariable(int offset) {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getParameterOffset() {
		return paramStart;
	}

	@Override
	public boolean isParameterOffset(int offset) {
		return (growsNegative && offset >= paramStart) || (!growsNegative && offset < paramStart);
	}

//	/**
//	 * 
//	 * @see ghidra.program.model.listing.StackFrame#setParameterOffset(int)
//	 */
//	@Override
//	public void setParameterOffset(int offset) {
//		paramStart = offset;
//		stackChanged();
//	}

	@Override
	public int getReturnAddressOffset() {
		return returnStart;
	}

	@Override
	public void setReturnAddressOffset(int offset) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Variable getVariableContaining(int offset) {
		Object key = Integer.valueOf(offset);
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
			if (var.getDataType().isDeleted()) {
				variables.remove(index);
			}
			else {
				return var;
			}
		}
		return null;
	}

	/**
	 * Get the size of the negative portion of the stack
	 *
	 * @return the negative portion size
	 */
	private int getNegativeSize() {
		int paramStart = getParameterOffset();
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
		int paramStart = getParameterOffset();
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
			if (var.getDataType().isDeleted()) {
				variables.remove(index);
				continue;
			}
			int start = var.getStackOffset();
			if (start >= 0 || start > getParameterOffset()) {
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
	 * Method getAllVariables.
	 * @return StackVariable[]
	 */
	private Variable[] getAllVariables() {
		if (variables.isEmpty()) {
			return emptyArray;
		}
		return variables.toArray(emptyArray);
	}

	/**
	 * Get all the stack variables in the positive portion of the stack.
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
			if (var.getDataType().isDeleted()) {
				variables.remove(index);
				continue;
			}
			int start = var.getStackOffset();
			if (start >= 0 && start >= paramStart) {
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
			if (var.getDataType().isDeleted()) {
				variables.remove(index);
				continue;
			}
			int start = var.getStackOffset();
			if (start >= 0 || start >= paramStart) {
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
			if (var.getDataType().isDeleted()) {
				variables.remove(index);
				continue;
			}
			int start = var.getStackOffset();
			if (start >= 0 && start >= paramStart) {
				break;
			}
		}
		if (index == length) {
			return 0;
		}
		return length - index;
	}

	@Override
	public Function getFunction() {
		return function;
	}

	/**
	 * Returns whether some other stack frame is "equivalent to" this one.
	 * The stack frame is considered equal to another even if they are each
	 * part of a different function.
	 * @param obj the object to compare for equality.
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}
		if (!(obj instanceof StackFrame)) {
			return false;
		}
		StackFrame otherFrame = (StackFrame) obj;
		Variable[] otherVars = otherFrame.getStackVariables();
		if ((this.getLocalSize() != otherFrame.getLocalSize()) ||
			(this.paramStart != otherFrame.getParameterOffset()) ||
			(this.returnStart != otherFrame.getReturnAddressOffset()) ||
			(this.variables.size() != otherVars.length)) {
			return false;
		}
		Iterator<Variable> myIter = this.variables.iterator();
		for (int i = 0; i < otherVars.length && myIter.hasNext(); i++) {
			Variable myVar = myIter.next();
			if (!(myVar.equals(otherVars[i]))) {
				return false;
			}
		}
		return true;
	}
}
