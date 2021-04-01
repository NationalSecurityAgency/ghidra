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
package ghidra.trace.database.symbol;

import static ghidra.lifecycle.Unfinished.TODO;

import java.util.ArrayList;
import java.util.Arrays;

import ghidra.lifecycle.Unfinished;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.LockHold;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class DBTraceFunctionStackFrame implements StackFrame, Unfinished {
	protected final DBTraceFunctionSymbol function;
	protected Variable[] variables;
	protected boolean growsNegative;
	protected boolean valid;

	public DBTraceFunctionStackFrame(DBTraceFunctionSymbol function) {
		this.function = function;
		this.growsNegative = function.getTrace().getBaseCompilerSpec().stackGrowsNegative();
		this.valid = false;
	}

	protected synchronized boolean checkIsValid() {
		if (!function.isDeleted()) {
			if (!valid) {
				growsNegative = function.getTrace().getBaseCompilerSpec().stackGrowsNegative();
				variables = function.getVariables(VariableFilter.COMPOUND_STACK_VARIABLE_FILTER);
				Arrays.sort(variables, StackVariableComparator.get());
				valid = true;
			}
			return true;
		}
		return false;
	}

	@Override
	public DBTraceFunctionSymbol getFunction() {
		return function;
	}

	@Override
	public int getFrameSize() {
		try (LockHold hold = LockHold.lock(function.manager.lock.readLock())) {
			return getParameterSize() + getLocalSize();
		}
	}

	@Override
	public int getLocalSize() {
		try (LockHold hold = LockHold.lock(function.manager.lock.readLock())) {
			checkIsValid();

			Integer base = VariableUtilities.getBaseStackParamOffset(function);
			int baseOffset = base == null ? 0 : base.intValue();

			if (growsNegative) {
				if (variables.length == 0) {
					return baseOffset;
				}
				Variable v = variables[0];
				if (!(v instanceof LocalVariable)) {
					return baseOffset;
				}
				int offset = Math.max(0, (int) v.getLastStorageVarnode().getOffset());
				return baseOffset - offset;
			}
			// else Positive growth
			if (variables.length == 0) {
				return -baseOffset;
			}
			Variable v = variables[variables.length - 1];
			if (!(v instanceof LocalVariable)) {
				return -baseOffset;
			}
			Varnode stackVarnode = v.getLastStorageVarnode();
			int len = stackVarnode.getSize();
			int offset = Math.max(0, (int) stackVarnode.getOffset());
			return offset - baseOffset + len;
		}
	}

	@Override
	public int getParameterSize() {
		try (LockHold hold = LockHold.lock(function.manager.lock.readLock())) {
			checkIsValid();

			Integer base = VariableUtilities.getBaseStackParamOffset(function);
			int baseOffset = base == null ? 0 : base.intValue();

			if (growsNegative) {
				if (variables.length == 0) {
					return 0;
				}
				Variable v = variables[variables.length - 1];
				if (!(v instanceof Parameter)) {
					return 0;
				}
				Varnode stackVarnode = v.getLastStorageVarnode();
				int len = stackVarnode.getSize();
				int offset = (int) stackVarnode.getOffset();
				return offset - baseOffset + len;
			}
			// else Positive growth
			if (variables.length == 0) {
				return 0;
			}
			Variable v = variables[0];
			if (!(v instanceof Parameter)) {
				return 0;
			}
			int offset = (int) v.getLastStorageVarnode().getOffset();
			return baseOffset - offset;
		}
	}

	@Override
	public int getParameterOffset() {
		Integer base = VariableUtilities.getBaseStackParamOffset(function);
		return base == null ? UNKNOWN_PARAM_OFFSET : base.intValue();
	}

	@Override
	public boolean isParameterOffset(int offset) {
		Integer base = VariableUtilities.getBaseStackParamOffset(function);
		if (base == null) {
			return false;
		}
		if (growsNegative) {
			return offset >= base.intValue();
		}
		return offset < base.intValue();
	}

	@Override
	public void setLocalSize(int size) {
		// TODO: Is this ever called?
		TODO();
	}

	@Override
	public void setReturnAddressOffset(int offset) {
		function.setReturnAddressOffset(offset);
	}

	@Override
	public int getReturnAddressOffset() {
		return function.getReturnAddressOffset();
	}

	@Override
	public Variable getVariableContaining(int offset) {
		try (LockHold hold = LockHold.lock(function.manager.lock.readLock())) {
			int index = Arrays.binarySearch(variables, offset, StackVariableComparator.get());
			if (index >= 0) {
				return variables[index];
			}
			/**
			 * index is -insertionPoint - 1 insertionPoint is index of first element greater than
			 * the key, i.e., where it would be inserted. We want the last element less than they
			 * key
			 */
			index = -index - 2;
			if (index < 0) {
				return null;
			}
			// We have the preceding variable. See if it contains the offset.
			Variable var = variables[index];
			Varnode stackVarnode = var.getLastStorageVarnode();
			int varOffset = (int) stackVarnode.getOffset();
			if (offset < varOffset + stackVarnode.getSize()) {
				return var;
			}
			return null;
		}
	}

	@Override
	public AbstractDBTraceVariableSymbol createVariable(String name, int offset, DataType dataType,
			SourceType source) throws DuplicateNameException, InvalidInputException {
		try (LockHold hold = LockHold.lock(function.manager.lock.writeLock())) {
			checkIsValid();
			if (dataType != null) {
				dataType = dataType.clone(function.getTrace().getDataTypeManager());
			}
			Variable var = new LocalVariableImpl(name, dataType, offset, function.getProgram());
			AbstractDBTraceVariableSymbol result;
			if (isParameterOffset(offset)) {
				// Compute ordinal
				int ordinal = function.getParameterCount();
				Parameter[] params = getParameters();
				if (growsNegative) {
					for (int i = params.length - 1; i >= 0; i--) {
						Parameter p = params[i];
						if (offset <= p.getLastStorageVarnode().getOffset()) {
							ordinal = p.getOrdinal();
						}
					}
				}
				else {
					for (int i = 0; i < params.length; i++) {
						Parameter p = params[i];
						if (offset <= p.getLastStorageVarnode().getOffset()) {
							ordinal = p.getOrdinal();
						}
					}
				}

				result = function.insertParameter(ordinal, var, source);
			}
			else {
				result = function.addLocalVariable(var, source);
			}

			/**
			 * TODO: The original implementation tries to implicitly enable custom storage if:
			 * 
			 * 1) We're inserting a parameter,
			 * 
			 * 2) Custom storage is not already enabled, and
			 * 
			 * 3) The variable would not be stored where specified without custom storage
			 * 
			 * Unless it is required or jarring to the user, I'm going to forego this rule. Let the
			 * user manually enable custom storage if precise parameter placement via this method is
			 * desired.
			 * 
			 * The issue in the original implementation is: It detects (3) by inserting the variable
			 * and then checking where it was assigned storage. By this time, the function will have
			 * already re-assigned the other variables' storage. Despite that, the method re-assigns
			 * the new variable to the desired storage. This may leave the others in an unexpected
			 * or bad state.
			 * 
			 * Perhaps it can be fixed: Instead of re-assigning the storage, deleting the new
			 * parameter, enable custom storage, and then re-insert the desired parameter.
			 */
			return result;
		}
	}

	@Override
	public void clearVariable(int offset) {
		try (LockHold hold = LockHold.lock(function.manager.lock.writeLock())) {
			checkIsValid();
			Variable var = getVariableContaining(offset);
			/**
			 * TODO: The original implementation implicitly enables custom storage if:
			 * 
			 * 1) A variable exists at the given offset, and
			 * 
			 * 2) Custom storage is not already enabled
			 * 
			 * Unless it is required or jarring to the user, I'm going to forego this rule. Let the
			 * user manually enable custom storage if precise parameter placement via this method is
			 * desired.
			 */
			if (var != null) {
				function.removeVariable(var);
			}
		}
	}

	@Override
	public Variable[] getStackVariables() {
		try (LockHold hold = LockHold.lock(function.manager.lock.readLock())) {
			checkIsValid();
			return Arrays.copyOf(variables, variables.length);
		}
	}

	@Override
	public Parameter[] getParameters() {
		try (LockHold hold = LockHold.lock(function.manager.lock.readLock())) {
			checkIsValid();
			ArrayList<Parameter> list = new ArrayList<Parameter>();
			for (Variable v : variables) {
				if (v instanceof Parameter) {
					list.add((Parameter) v);
				}
			}
			return list.toArray(new Parameter[list.size()]);
		}
	}

	@Override
	public LocalVariable[] getLocals() {
		try (LockHold hold = LockHold.lock(function.manager.lock.readLock())) {
			checkIsValid();
			ArrayList<LocalVariable> list = new ArrayList<LocalVariable>();
			for (Variable v : variables) {
				if (v instanceof LocalVariable) {
					list.add((LocalVariable) v);
				}
			}
			return list.toArray(new LocalVariable[list.size()]);
		}
	}

	@Override
	public boolean growsNegative() {
		try (LockHold hold = LockHold.lock(function.manager.lock.readLock())) {
			return growsNegative;
		}
	}

	protected synchronized void invalidate() {
		valid = false;
	}
}
