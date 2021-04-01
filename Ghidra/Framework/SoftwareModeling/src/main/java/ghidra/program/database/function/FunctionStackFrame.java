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

import java.util.*;

import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

class FunctionStackFrame implements StackFrame {

	// NOTE: Program stack frame may contain compound variables which have a stack component

	private Variable[] variables;
	private FunctionDB function;
	private boolean stackGrowsNegative;
	private boolean invalid;

	/**
	 * Construct a function stack frame.
	 * @param function
	 * @param variables
	 */
	FunctionStackFrame(FunctionDB function) {
		this.function = function;
		stackGrowsNegative = function.getProgram().getCompilerSpec().stackGrowsNegative();
		invalid = true;
	}

	boolean checkIsValid() {
		if (function.isDeleted()) {
			return false;
		}
		if (invalid) {
			stackGrowsNegative =
				function.getFunctionManager().getProgram().getCompilerSpec().stackGrowsNegative();
			variables = function.getVariables(VariableFilter.COMPOUND_STACK_VARIABLE_FILTER);
			Arrays.sort(variables, StackVariableComparator.get());
			invalid = false;
		}
		return true;
	}

	void checkDeleted() {
		if (!checkIsValid()) {
			throw new ConcurrentModificationException("Object has been deleted.");
		}
	}

	void setInvalid() {
		invalid = true;
	}

	@Override
	public Function getFunction() {
		return function;
	}

	@Override
	public Variable createVariable(String name, int offset, DataType dataType, SourceType source)
			throws DuplicateNameException, InvalidInputException {

		// WARNING! Stack parameters will be created even if calling convention
		// does not specify stack inputs

		function.manager.lock.acquire();
		try {
			checkDeleted();
			if (dataType != null) {
				dataType = dataType.clone(function.getProgram().getDataTypeManager());
			}
			Variable var = new LocalVariableImpl(name, dataType, offset, function.getProgram());
			if (isParameterOffset(offset)) {

				// Determine ordinal insertion point
				int ordinal = function.getParameterCount();
				Parameter[] params = getParameters();
				if (stackGrowsNegative) {
					for (int i = params.length - 1; i >= 0; i--) {
						if (offset <= params[i].getLastStorageVarnode().getOffset()) {
							ordinal = params[i].getOrdinal();
						}
					}
				}
				else {
					for (Parameter param : params) {
						if (offset >= param.getLastStorageVarnode().getOffset()) {
							ordinal = param.getOrdinal();
						}
					}
				}
				var = function.insertParameter(ordinal, var, source);
			}
			else {
				var = function.addLocalVariable(var, source);
			}

			if ((var instanceof Parameter) && !function.hasCustomVariableStorage() &&
				(!var.isStackVariable() || var.getStackOffset() != offset)) {
				// TODO: setting custom storage here may lock in bad stack offsets created when FunctionDB
				//   dynamically reshuffles storage to satisfy the insertParameter call above.
				//   the setDataType method below only fixes 1 variable
				function.setCustomVariableStorage(true);
				VariableStorage storage =
					new VariableStorage(function.getProgram(), offset, var.getLength());
				var.setDataType(var.getDataType(), storage, true, source);
			}

			return var;
		}
		finally {
			function.manager.lock.release();
		}
	}

	/*
	 *  (non-Javadoc)
	 * @see ghidra.program.model.listing.StackFrame#getStackVariables()
	 */
	@Override
	public Variable[] getStackVariables() {
		function.manager.lock.acquire();
		try {
			checkIsValid();
			Variable[] temp = new Variable[variables.length];
			System.arraycopy(variables, 0, temp, 0, variables.length);
			return temp;
		}
		finally {
			function.manager.lock.release();
		}
	}

	/*
	 *  (non-Javadoc)
	 * @see ghidra.program.model.listing.StackFrame#getLocals()
	 */
	@Override
	public Variable[] getLocals() {
		function.manager.lock.acquire();
		try {
			checkIsValid();
			ArrayList<Variable> list = new ArrayList<Variable>();
			for (Variable variable : variables) {
				if (!(variable instanceof Parameter)) {
					list.add(variable);
				}
			}
			Variable[] vars = new Variable[list.size()];
			return list.toArray(vars);
		}
		finally {
			function.manager.lock.release();
		}
	}

	/*
	 *  (non-Javadoc)
	 * @see ghidra.program.model.listing.StackFrame#getParameters()
	 */
	@Override
	public Parameter[] getParameters() {
		function.manager.lock.acquire();
		try {
			checkIsValid();
			ArrayList<Parameter> list = new ArrayList<Parameter>();
			for (Variable variable : variables) {
				if (variable instanceof Parameter) {
					list.add((Parameter) variable);
				}
			}
			Parameter[] vars = new Parameter[list.size()];
			return list.toArray(vars);
		}
		finally {
			function.manager.lock.release();
		}
	}

	/*
	 *  (non-Javadoc)
	 * @see ghidra.program.model.listing.StackFrame#getFrameSize()
	 */
	@Override
	public int getFrameSize() {
		function.manager.lock.acquire();
		try {
			return getParameterSize() + getLocalSize();
		}
		finally {
			function.manager.lock.release();
		}
	}

	/*
	 *  (non-Javadoc)
	 * @see ghidra.program.model.listing.StackFrame#getLocalSize()
	 */
	@Override
	public int getLocalSize() {
		function.manager.lock.acquire();
		try {
			checkIsValid();

			int baseOffset = 0;
			Integer base = VariableUtilities.getBaseStackParamOffset(function);
			if (base != null) {
				baseOffset = (int) base.longValue();
			}

			// Negative growth
			if (stackGrowsNegative) {
				if (variables.length != 0 && !(variables[0] instanceof Parameter)) {
					int offset = (int) variables[0].getLastStorageVarnode().getOffset();
					if (offset > 0) {
						offset = 0;
					}
					return baseOffset - offset;
				}
				return baseOffset;
			}

			// Positive growth
			int index = variables.length - 1;
			if (index < 0) {
				return -baseOffset;
			}
			if (!(variables[index] instanceof Parameter)) {
				Varnode stackVarnode = variables[index].getLastStorageVarnode();
				int len = stackVarnode.getSize();
				int offset = (int) stackVarnode.getOffset();
				if (offset < 0) {
					offset = 0;
				}
				return offset - baseOffset + len;
			}
			return -baseOffset;
		}
		finally {
			function.manager.lock.release();
		}
	}

	/*
	 *  (non-Javadoc)
	 * @see ghidra.program.model.listing.StackFrame#growsNegative()
	 */
	@Override
	public boolean growsNegative() {
		return stackGrowsNegative;
	}

	/*
	 *  (non-Javadoc)
	 * @see ghidra.program.model.listing.StackFrame#setLocalSize(int)
	 */
	@Override
	public void setLocalSize(int size) {
		// TODO: Has no real affect
		function.setLocalSize(size);
	}

	/*
	 *  (non-Javadoc)
	 * @see ghidra.program.model.listing.StackFrame#getParameterSize()
	 */
	@Override
	public int getParameterSize() {
		function.manager.lock.acquire();
		try {
			checkIsValid();

			int baseOffset = 0;
			Integer base = VariableUtilities.getBaseStackParamOffset(function);
			if (base != null) {
				baseOffset = (int) base.longValue();
			}

			// Negative growth
			if (stackGrowsNegative) {
				int index = variables.length - 1;
				if (index < 0) {
					return 0;
				}
				if (variables[index] instanceof Parameter) {
					Varnode stackVarnode = variables[index].getLastStorageVarnode();
					int len = stackVarnode.getSize();
					int stackOffset = (int) stackVarnode.getOffset();
					return stackOffset - baseOffset + len;
				}
				return 0;
			}

			// Positive growth
			if (variables.length != 0 && (variables[0] instanceof Parameter)) {
				int stackOffset = (int) variables[0].getLastStorageVarnode().getOffset();
				return baseOffset - stackOffset;
			}
			return 0;
		}
		finally {
			function.manager.lock.release();
		}
	}

	/**
	 * @return the number of parameters which occupy stack storage
	 */
	int getParameterCount() {
		function.manager.lock.acquire();
		try {
			checkIsValid();
			int cnt = 0;
			for (Variable variable : variables) {
				if (variable instanceof Parameter) {
					++cnt;
				}
			}
			return cnt;
		}
		finally {
			function.manager.lock.release();
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see ghidra.program.model.listing.StackFrame#clearVariable(int)
	 */
	@Override
	public void clearVariable(int offset) {

		// WARNING! removing Stack parameters from the stack frame will enable custom storage

		function.manager.lock.acquire();
		try {
			checkDeleted();
			Variable var = getVariableContaining(offset);
			if (var != null) {
				if (!function.hasCustomVariableStorage()) {
					function.setCustomVariableStorage(true);
				}
				function.removeVariable(var);
			}
		}
		finally {
			function.manager.lock.release();
		}
	}

	/*
	 *  (non-Javadoc)
	 * @see ghidra.program.model.listing.StackFrame#getParameterOffset()
	 */
	@Override
	public int getParameterOffset() {
		Integer baseOffset = VariableUtilities.getBaseStackParamOffset(function);
		return baseOffset != null ? (int) baseOffset.longValue() : UNKNOWN_PARAM_OFFSET;
	}

//	/**
//	 * @see ghidra.program.model.listing.StackFrame#setParameterOffset(int)
//	 */
//	@Override
//	public void setParameterOffset(int offset) throws InvalidInputException {
//		// don't set the parameter offset to an unknown offset
//		if (offset == UNKNOWN_PARAM_OFFSET) {
//			return;
//		}
//		function.setParameterOffset(offset);
//	}

	/*
	 *  (non-Javadoc)
	 * @see ghidra.program.model.listing.StackFrame#getReturnAddressOffset()
	 */
	@Override
	public int getReturnAddressOffset() {
		return function.getReturnAddressOffset();
	}

	/*
	 *  (non-Javadoc)
	 * @see ghidra.program.model.listing.StackFrame#setReturnAddressOffset(int)
	 */
	@Override
	public void setReturnAddressOffset(int offset) {
		function.setReturnAddressOffset(offset);
	}

	/*
	 *  (non-Javadoc)
	 * @see ghidra.program.model.listing.StackFrame#getVariableContaining(int)
	 */
	@Override
	public Variable getVariableContaining(int offset) {
		function.manager.lock.acquire();
		try {
			checkIsValid();
			Object key = new Integer(offset);
			int index = Arrays.binarySearch(variables, key, StackVariableComparator.get());
			if (index >= 0) {
				return variables[index];
			}
			index = -index - 1;
			index = index - 1;
			if (index < 0) {
				return null;
			}
			Variable var = variables[index];
			Varnode stackVarnode = var.getLastStorageVarnode();
			int stackOffset = (int) stackVarnode.getOffset();
			if ((stackOffset + stackVarnode.getSize()) > offset) {
				return var;
			}
			return null;
		}
		finally {
			function.manager.lock.release();
		}
	}

	/**
	 * Get the size of the negative portion of the stack
	 *
	 * @return the negative portion size
	 */
//	private int getNegativeSize() {
//		int paramStart = function.getParameterOffset();
//		if (variables.length == 0) {
//			return (stackGrowsNegative ? 0 : -paramStart);
//		}
//
//		if (variables[0].getStackOffset() >= 0) {
//			return (stackGrowsNegative ? 0 : -paramStart);
//		}
//		return 0 - variables[0].getStackOffset();
//	}

	/**
	 * Get the size of the positive portion of the stack (including 0)
	 *
	 * @return the positive portion size
	 */
//	private int getPositiveSize() {
//		int paramStart = function.getParameterOffset();
//		if (variables.length == 0) {
//			return (stackGrowsNegative ? paramStart : 0);
//		}
//		StackVariable var = variables[variables.length - 1];
//		if (var.getStackOffset() < 0) {
//			return (stackGrowsNegative ? paramStart : 0);
//		}
//		return var.getStackOffset() + var.getLength();
//	}

	/**
	 * Get a count of all the stack variables in the negative portion of the
	 * frame. This EXCLUDES any variables defined before the parameter offset if
	 * the parameter offset is negative.
	 */
//	private int getNegativeCount() {
//		if (variables.length == 0) {
//			return 0;
//		}
//		int paramStart = function.getParameterOffset();
//		int length = variables.length;
//
//		// find the end of the negatives
//		int index = 0;
//		for (index = 0; index < length; index++) {
//			int start = variables[index].getStackOffset();
//			if (start >= 0 || start >= paramStart) {
//				break;
//			}
//		}
//		if (index == 0) {
//			return 0;
//		}
//		return index;
//	}

	/**
	 * Get all the stack variables in the postive portion of the stack.
	 * This EXCLUDES any variables defined before the parameter offset if the
	 * parameter offset is positive.
	 *
	 * @return an array of variables defined on the positive portion of the frame.
	 */
//	private int getPositiveCount() {
//		if (variables.length == 0) {
//			return 0;
//		}
//		int paramStart = function.getParameterOffset();
//		int length = variables.length;
//
//		// find the end of the negatives
//		int index = 0;
//		for (index = 0; index < length; index++) {
//			int start = variables[index].getStackOffset();
//			if (start >= 0 && start >= paramStart) {
//				break;
//			}
//		}
//		if (index == length) {
//			return 0;
//		}
//		return length - index;
//	}

	/**
	 * Returns true if specified offset could correspond to a parameter
	 * @param offset
	 */
	@Override
	public boolean isParameterOffset(int offset) {
		// If we have conventions, try to figure out where the parameters do start
		//   if no conventions or stack parameter defs, assume 0
		//
		Integer baseOffset = VariableUtilities.getBaseStackParamOffset(function);

		// if there is no offset, then input is not passed on the stack
		if (baseOffset == null) {
			return false;
		}
		return (stackGrowsNegative && offset >= baseOffset) ||
			(!stackGrowsNegative && offset < baseOffset);
	}

	/**
	 * Returns whether some other stack frame is "equivalent to" this one.
	 * The stack frame is considered equal to another even if they are each
	 * part of a different function.
	 */
	@Override
	public boolean equals(Object obj) {
		checkIsValid();

		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		FunctionStackFrame otherFrame = (FunctionStackFrame) obj;

		if ((this.getLocalSize() != otherFrame.getLocalSize()) ||
			(this.getParameterOffset() != otherFrame.getParameterOffset()) ||
			(this.getReturnAddressOffset() != otherFrame.getReturnAddressOffset()) ||
			(this.variables.length != otherFrame.variables.length)) {
			return false;
		}

		for (int i = 0; i < variables.length; i++) {
			if (!variables[i].equals(otherFrame.variables[i])) {
				return false;
			}
		}
		return true;
	}

}
